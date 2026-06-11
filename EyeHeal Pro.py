import pygame
import cv2
import mediapipe as mp
import numpy as np
import sqlite3
import hashlib
import requests
import time
import threading
import os
import re
import math
import tkinter as tk
from tkinter import filedialog
from datetime import datetime

# PDF
try:
    import pdfplumber
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ============================================================
# 1. الإعدادات العامة
# ============================================================
class Config:
    W, H         = 1366, 768
    BG           = (5, 10, 20)
    SIDEBAR_COLOR= (10, 20, 35)
    ACCENT       = (0, 200, 255)
    RED          = (255, 60, 60)
    GREEN        = (0, 255, 150)
    YELLOW       = (255, 220, 0)
    ORANGE       = (255, 140, 0)
    WHITE        = (240, 240, 240)
    CARD_BG      = (20, 30, 50)
    INPUT_BG     = (10, 15, 25)
    API_KEY      = os.environ.get("GEMINI_API_KEY", "AIzaSyCE1cMjoeEp_KwA3GSCOEIpOWaq_X4SWJM")
    MODEL_NAME   = "gemini-2.5-flash"
    MAX_INPUT_LEN= 60
    ALLOWED_DOMAINS = {"generativelanguage.googleapis.com"}
    RATE_LIMIT_PER_MIN = 10
    MAX_RESPONSE_SIZE  = 1_000_000


# ============================================================
# 2. الـ Firewall
# ============================================================
class Firewall:
    def __init__(self):
        self._lock          = threading.Lock()
        self._req_times     = []
        self._log_path      = "firewall_audit.log"
        self._blocked_count = 0

    def _log(self, level, msg):
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {msg}\n"
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
        print(line.strip())

    def _check_domain(self, url):
        try:
            domain  = url.split("//")[-1].split("/")[0].split("?")[0]
            allowed = domain in Config.ALLOWED_DOMAINS
            if not allowed:
                self._log("BLOCK", f"Unauthorized domain: {domain}")
                self._blocked_count += 1
            return allowed
        except Exception:
            return False

    def _check_rate(self):
        now = time.time()
        with self._lock:
            self._req_times = [t for t in self._req_times if now - t < 60]
            if len(self._req_times) >= Config.RATE_LIMIT_PER_MIN:
                self._log("BLOCK", f"Rate limit exceeded")
                self._blocked_count += 1
                return False
            self._req_times.append(now)
        return True

    @staticmethod
    def sanitize_text(text):
        patterns = [
            r"ignore (all |previous |above )?instructions?",
            r"disregard (all |previous )?",
            r"you are now", r"act as (a |an )?",
            r"jailbreak", r"<\s*script.*?>",
            r"system\s*:", r"assistant\s*:",
        ]
        cleaned = text
        for p in patterns:
            cleaned = re.sub(p, "", cleaned, flags=re.IGNORECASE)
        return cleaned.strip()

    def safe_post(self, url, payload, timeout=15):
        if not self._check_domain(url):
            return None, "FIREWALL: Domain not allowed"
        if not self._check_rate():
            return None, "FIREWALL: Rate limit exceeded"
        try:
            for part in payload.get("contents", [{}])[0].get("parts", []):
                if "text" in part:
                    orig = part["text"]
                    part["text"] = self.sanitize_text(orig)
                    if part["text"] != orig:
                        self._log("WARN", "Prompt injection cleaned")
        except Exception:
            pass
        self._log("INFO", f"Outbound request to: {url.split('?')[0]}")
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if len(resp.content) > Config.MAX_RESPONSE_SIZE:
                self._log("BLOCK", "Response too large")
                return None, "FIREWALL: Response too large"
            self._log("INFO", f"Response OK — status={resp.status_code}")
            return resp, None
        except requests.exceptions.Timeout:
            return None, "Request timed out"
        except Exception as e:
            return None, str(e)

    @property
    def blocked_count(self):
        return self._blocked_count


# ============================================================
# 3. قارئ PDF
# ============================================================
class PDFAnalyzer:
    @staticmethod
    def open_file_dialog():
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askopenfilename(
            title="Select Patient PDF Report",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")]
        )
        root.destroy()
        return path if path else None

    @staticmethod
    def extract_text(pdf_path):
        if not PDF_AVAILABLE:
            return "", "pdfplumber not installed"
        try:
            pages = []
            with pdfplumber.open(pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    t = page.extract_text()
                    if t:
                        pages.append(f"[Page {i+1}]\n{t}")
            full = "\n\n".join(pages)
            if not full.strip():
                return "", "Could not extract text"
            return full[:4000], None
        except Exception as e:
            return "", str(e)

    @staticmethod
    def parse_risks_from_text(text):
        risk_l, risk_r = 0, 0
        for p in [r"left\s*eye[:\s]+(\d+)%", r"\bOS[:\s]+(\d+)%"]:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                risk_l = min(int(m.group(1)), 100)
                break
        for p in [r"right\s*eye[:\s]+(\d+)%", r"\bOD[:\s]+(\d+)%"]:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                risk_r = min(int(m.group(1)), 100)
                break
        return risk_l, risk_r


# ============================================================
# 4. مولّد تقرير PDF
# ============================================================
class ReportGenerator:
    @staticmethod
    def save_dialog():
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.asksaveasfilename(
            title="Save Patient Report",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")]
        )
        root.destroy()
        return path if path else None

    @staticmethod
    def generate(patient_name, age, risk_l, risk_r, plan_text, sessions, save_path):
        if not REPORTLAB_AVAILABLE:
            return False, "reportlab not installed. Run: pip install reportlab"
        try:
            doc    = SimpleDocTemplate(save_path, pagesize=A4,
                                       topMargin=2*cm, bottomMargin=2*cm,
                                       leftMargin=2*cm, rightMargin=2*cm)
            styles = getSampleStyleSheet()
            story  = []

            title_style = ParagraphStyle('title', parent=styles['Title'],
                                         fontSize=22, textColor=colors.HexColor('#0088cc'),
                                         spaceAfter=6)
            head_style  = ParagraphStyle('head', parent=styles['Heading2'],
                                         fontSize=13, textColor=colors.HexColor('#005577'),
                                         spaceBefore=12, spaceAfter=4)
            body_style  = ParagraphStyle('body', parent=styles['Normal'],
                                         fontSize=10, leading=15)

            story.append(Paragraph("OptiPath AI — Patient Treatment Report", title_style))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", body_style))
            story.append(Spacer(1, 0.4*cm))

            # بيانات المريض
            story.append(Paragraph("Patient Information", head_style))
            data = [
                ["Name", patient_name],
                ["Age",  age],
                ["Left Eye Risk",  f"{risk_l}%"],
                ["Right Eye Risk", f"{risk_r}%"],
                ["Exam Date", datetime.now().strftime("%Y-%m-%d")],
            ]
            t = Table(data, colWidths=[5*cm, 10*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#e8f4f8')),
                ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE',   (0,0), (-1,-1), 10),
                ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0,0), (-1,-1),
                 [colors.white, colors.HexColor('#f5fbff')]),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.4*cm))

            # خطة العلاج
            story.append(Paragraph("AI Treatment Plan", head_style))
            for line in plan_text.split('\n'):
                if line.strip():
                    safe = line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                    story.append(Paragraph(safe, body_style))

            # سجل الجلسات
            if sessions:
                story.append(Spacer(1, 0.4*cm))
                story.append(Paragraph("Exercise Session History", head_style))
                sess_data = [["Date", "Exercise", "Duration (sec)", "Score"]]
                for s in sessions[-10:]:
                    sess_data.append([s.get('date',''), s.get('exercise',''),
                                      str(s.get('duration',0)), str(s.get('score',0))])
                t2 = Table(sess_data, colWidths=[4*cm, 5*cm, 4*cm, 2*cm])
                t2.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0088cc')),
                    ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
                    ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
                    ('FONTSIZE',   (0,0), (-1,-1), 9),
                    ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1),
                     [colors.white, colors.HexColor('#f5fbff')]),
                ]))
                story.append(t2)

            doc.build(story)
            return True, save_path
        except Exception as e:
            return False, str(e)


# ============================================================
# 5. قاعدة البيانات
# ============================================================
class Database:
    def __init__(self):
        try:
            self.conn = sqlite3.connect("optipath_data.db", check_same_thread=False)
            self._lock= threading.Lock()
            self.cur  = self.conn.cursor()
            self.setup()
            self._records_cache = None
            self._cache_dirty   = True
        except Exception as e:
            print(f"Database Init Error: {e}")

    def setup(self):
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS doctors (email TEXT PRIMARY KEY, name TEXT, pwd TEXT)"
        )
        self.cur.execute("""CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, age TEXT, risk_l REAL, risk_r REAL,
            plan TEXT, date TEXT, source TEXT)""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT, exercise TEXT,
            duration INTEGER, score INTEGER, date TEXT)""")
        try:
            self.cur.execute("ALTER TABLE patients ADD COLUMN source TEXT")
        except Exception:
            pass
        self.conn.commit()

    @staticmethod
    def hash_pwd(pwd):
        return hashlib.sha256(pwd.strip().encode()).hexdigest()

    def register_doctor(self, name, email, pwd):
        try:
            name = name.strip(); email = email.strip().lower(); pwd = pwd.strip()
            if not name or not email or not pwd:
                return "empty"
            with self._lock:
                self.cur.execute("SELECT email FROM doctors WHERE email=?", (email,))
                if self.cur.fetchone():
                    return "exists"
                self.cur.execute(
                    "INSERT INTO doctors (name,email,pwd) VALUES (?,?,?)",
                    (name, email, self.hash_pwd(pwd))
                )
                self.conn.commit()
            return True
        except Exception as e:
            print(f"Registration Error: {e}")
            return False

    def verify_doctor(self, email, pwd):
        try:
            email = email.strip().lower()
            with self._lock:
                self.cur.execute(
                    "SELECT name FROM doctors WHERE email=? AND pwd=?",
                    (email, self.hash_pwd(pwd))
                )
                res = self.cur.fetchone()
            return res[0] if res else None
        except Exception:
            return None

    def save_patient(self, name, age, rl, rr, plan, source="camera"):
        try:
            date = datetime.now().strftime("%Y-%m-%d %H:%M")
            with self._lock:
                self.cur.execute(
                    "INSERT INTO patients (name,age,risk_l,risk_r,plan,date,source) VALUES (?,?,?,?,?,?,?)",
                    (name, age, rl, rr, plan, date, source)
                )
                self.conn.commit()
            self._cache_dirty = True
            return True
        except Exception as e:
            print(f"Save Patient Error: {e}")
            return False

    def save_session(self, patient_name, exercise, duration, score):
        try:
            date = datetime.now().strftime("%Y-%m-%d %H:%M")
            with self._lock:
                self.cur.execute(
                    "INSERT INTO sessions (patient_name,exercise,duration,score,date) VALUES (?,?,?,?,?)",
                    (patient_name, exercise, duration, score, date)
                )
                self.conn.commit()
            return True
        except Exception:
            return False

    def get_sessions(self, patient_name):
        try:
            with self._lock:
                self.cur.execute(
                    "SELECT exercise,duration,score,date FROM sessions WHERE patient_name=? ORDER BY id DESC LIMIT 20",
                    (patient_name,)
                )
                rows = self.cur.fetchall()
            return [{"exercise": r[0], "duration": r[1], "score": r[2], "date": r[3]} for r in rows]
        except Exception:
            return []

    def get_records(self):
        if self._cache_dirty or self._records_cache is None:
            try:
                with self._lock:
                    self.cur.execute(
                        "SELECT name,age,risk_l,risk_r,date,source FROM patients ORDER BY id DESC"
                    )
                    self._records_cache = self.cur.fetchall()
                self._cache_dirty = False
            except Exception:
                self._records_cache = []
        return self._records_cache


# ============================================================
# 6. محرك تحليل العين
# ============================================================
class EyeAnalyzer:
    LEFT_EYE  = [362, 385, 387, 263, 373, 380]
    RIGHT_EYE = [33,  160, 158,  133, 153, 144]

    def __init__(self):
        self.mp_face   = mp.solutions.face_mesh
        self.face_mesh = self.mp_face.FaceMesh(
            max_num_faces=1, refine_landmarks=True,
            min_detection_confidence=0.5, min_tracking_confidence=0.5
        )
        self._history_l = []
        self._history_r = []
        self._history_size = 30

    @staticmethod
    def _ear(lm, idx, w, h):
        pts = np.array([[lm[i].x * w, lm[i].y * h] for i in idx])
        A = np.linalg.norm(pts[1] - pts[5])
        B = np.linalg.norm(pts[2] - pts[4])
        C = np.linalg.norm(pts[0] - pts[3])
        return (A + B) / (2.0 * C + 1e-6)

    def analyze(self, frame_bgr):
        h, w   = frame_bgr.shape[:2]
        rgb    = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        res    = self.face_mesh.process(rgb)
        risk_l = risk_r = 0
        ann    = frame_bgr.copy()
        if res.multi_face_landmarks:
            lm    = res.multi_face_landmarks[0].landmark
            ear_l = self._ear(lm, self.LEFT_EYE,  w, h)
            ear_r = self._ear(lm, self.RIGHT_EYE, w, h)
            self._history_l.append(ear_l)
            self._history_r.append(ear_r)
            if len(self._history_l) > self._history_size:
                self._history_l.pop(0); self._history_r.pop(0)
            avg_l = np.mean(self._history_l)
            avg_r = np.mean(self._history_r)
            def to_risk(e):
                return min(int(abs(e - 0.28) / 0.28 * 150), 95)
            risk_l = to_risk(avg_l)
            risk_r = to_risk(avg_r)
            for i in self.LEFT_EYE + self.RIGHT_EYE:
                cv2.circle(ann, (int(lm[i].x*w), int(lm[i].y*h)), 2, (0,200,255), -1)
            cv2.putText(ann, f"L:{avg_l:.2f}", (30,30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,150), 2)
            cv2.putText(ann, f"R:{avg_r:.2f}", (w-120,30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,150), 2)
        return risk_l, risk_r, ann


# ============================================================
# 7. محرك الذكاء الاصطناعي
# ============================================================
class AIEngine:
    def __init__(self, fw):
        self.fw = fw

    def generate_plan(self, name, age, rl, rr, callback, ctx=""):
        def task():
            ctx_sec = f"\n\nAdditional context:\n{ctx}" if ctx else ""
            prompt  = (
                f"As an ophthalmologist, create a 14-day amblyopia treatment plan for "
                f"{name}, age {age}. Left Eye Risk {rl}%, Right Eye Risk {rr}%.{ctx_sec}\n"
                f"Include daily patching hours and specific vision exercises."
            )
            url     = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                       f"{Config.MODEL_NAME}:generateContent?key={Config.API_KEY}")
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "systemInstruction": {"parts": [{"text": "You are a professional eye specialist. Output clearly and concisely."}]}
            }
            success = False
            for delay in [1, 2, 4]:
                resp, err = self.fw.safe_post(url, payload, timeout=20)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    text = (data.get('candidates',[{}])[0]
                            .get('content',{}).get('parts',[{}])[0].get('text',""))
                    if text:
                        callback(text); success = True; break
                if err: print(f"AI Error: {err}")
                time.sleep(delay)
            if not success:
                callback(
                    f"OFFLINE PLAN for {name}:\n"
                    f"1. Patch stronger eye (Right {rr}% risk) 4h daily.\n"
                    f"2. Near-vision activities during patching.\n"
                    f"3. Follow up in 2 weeks.\n(AI unavailable — local template)"
                )
        threading.Thread(target=task, daemon=True).start()


# ============================================================
# 8. التمارين التفاعلية
# ============================================================
class ExerciseEngine:
    """
    ثلاث تمارين:
    1. TRACKING  — تتبع كرة متحركة بالعين
    2. FOCUS     — تمرين التركيز: انقر على الدائرة لما تكبر
    3. PENCIL    — تمرين القلم: كرة بتتقرب وتتبعد
    """

    EXERCISES = ["TRACKING", "FOCUS", "PENCIL"]

    def __init__(self, screen, fonts):
        self.screen   = screen
        self.f_tiny, self.f_small, self.f_med, self.f_large = fonts
        self.active   = False
        self.ex_type  = "TRACKING"
        self.duration = 60        # ثانية
        self.start_t  = 0
        self.score    = 0
        self._init_tracking()
        self._init_focus()
        self._init_pencil()

    # ── تهيئة التمارين ────────────────────────────────────────
    def _init_tracking(self):
        self.tr_x   = Config.W // 2
        self.tr_y   = Config.H // 2
        self.tr_dx  = 3
        self.tr_dy  = 2
        self.tr_r   = 18

    def _init_focus(self):
        self.fc_x     = 683
        self.fc_y     = 384
        self.fc_r     = 15
        self.fc_grow  = True
        self.fc_max   = 55
        self.fc_speed = 0.5
        self.fc_clicked = False

    def _init_pencil(self):
        self.pc_z     = 0.0    # 0 = بعيد، 1 = قريب
        self.pc_dir   = 1
        self.pc_speed = 0.008

    # ── بدء / إيقاف ───────────────────────────────────────────
    def start(self, ex_type, duration=60):
        self.ex_type  = ex_type
        self.duration = duration
        self.start_t  = time.time()
        self.score    = 0
        self.active   = True
        self._init_tracking()
        self._init_focus()
        self._init_pencil()

    def stop(self):
        self.active = False

    def elapsed(self):
        return time.time() - self.start_t if self.active else 0

    def remaining(self):
        return max(0, self.duration - self.elapsed())

    def finished(self):
        return self.active and self.remaining() <= 0

    # ── معالجة الأحداث ────────────────────────────────────────
    def handle_click(self, mx, my):
        if not self.active:
            return
        if self.ex_type == "FOCUS":
            dist = math.hypot(mx - self.fc_x, my - self.fc_y)
            if dist < self.fc_r and self.fc_r > self.fc_max * 0.7:
                self.score += 1
                self.fc_r  = 15
                # انقل الدائرة لمكان عشوائي
                import random
                self.fc_x = random.randint(400, 950)
                self.fc_y = random.randint(150, 600)

    # ── التحديث ───────────────────────────────────────────────
    def update(self):
        if not self.active:
            return
        if self.ex_type == "TRACKING":
            self.tr_x += self.tr_dx
            self.tr_y += self.tr_dy
            if self.tr_x < 320 + self.tr_r or self.tr_x > Config.W - self.tr_r:
                self.tr_dx *= -1
            if self.tr_y < 80 + self.tr_r or self.tr_y > Config.H - self.tr_r:
                self.tr_dy *= -1

        elif self.ex_type == "FOCUS":
            if self.fc_grow:
                self.fc_r += self.fc_speed
                if self.fc_r >= self.fc_max:
                    self.fc_grow = False
            else:
                self.fc_r -= self.fc_speed * 2
                if self.fc_r <= 15:
                    self.fc_grow = True

        elif self.ex_type == "PENCIL":
            self.pc_z += self.pc_dir * self.pc_speed
            if self.pc_z >= 1.0:
                self.pc_dir = -1
            elif self.pc_z <= 0.0:
                self.pc_dir = 1

    # ── الرسم ─────────────────────────────────────────────────
    def draw(self):
        if not self.active:
            return

        # خلفية منطقة التمرين
        pygame.draw.rect(self.screen, (8, 18, 35),
                         (320, 60, Config.W - 320, Config.H - 60))

        # عنوان + مؤقت + نقاط
        rem  = int(self.remaining())
        mins = rem // 60
        secs = rem % 60
        timer_clr = Config.RED if rem < 10 else Config.GREEN
        self.screen.blit(
            self.f_large.render(f"Exercise: {self.ex_type}", True, Config.ACCENT),
            (340, 20)
        )
        self.screen.blit(
            self.f_med.render(f"Time: {mins:02d}:{secs:02d}", True, timer_clr),
            (900, 20)
        )
        self.screen.blit(
            self.f_med.render(f"Score: {self.score}", True, Config.YELLOW),
            (1100, 20)
        )

        # شريط الوقت
        ratio = self.remaining() / self.duration
        pygame.draw.rect(self.screen, (30, 40, 60), (320, 55, Config.W - 320, 8))
        pygame.draw.rect(self.screen, timer_clr,
                         (320, 55, int((Config.W - 320) * ratio), 8))

        # ── رسم كل تمرين ──
        if self.ex_type == "TRACKING":
            self._draw_tracking()
        elif self.ex_type == "FOCUS":
            self._draw_focus()
        elif self.ex_type == "PENCIL":
            self._draw_pencil()

        # تعليمات
        hints = {
            "TRACKING": "Follow the ball with your WEAK eye only",
            "FOCUS":    "Click the circle when it reaches MAXIMUM size",
            "PENCIL":   "Keep your eyes focused on the center dot as it moves"
        }
        hint = self.f_small.render(hints.get(self.ex_type, ""), True, (160, 160, 160))
        self.screen.blit(hint, (Config.W//2 - hint.get_width()//2, Config.H - 40))

    def _draw_tracking(self):
        # تأثير ذيل
        for i in range(8):
            alpha = 255 - i * 28
            r     = max(4, self.tr_r - i * 2)
            s     = pygame.Surface((r*2, r*2), pygame.SRCALPHA)
            pygame.draw.circle(s, (0, 200, 255, alpha), (r, r), r)
            self.screen.blit(s, (int(self.tr_x) - r, int(self.tr_y) - r))
        pygame.draw.circle(self.screen, Config.ACCENT,
                           (int(self.tr_x), int(self.tr_y)), self.tr_r)
        pygame.draw.circle(self.screen, Config.WHITE,
                           (int(self.tr_x) + 5, int(self.tr_y) - 5), 5)

    def _draw_focus(self):
        r   = int(self.fc_r)
        clr = Config.GREEN if self.fc_r > self.fc_max * 0.7 else Config.ACCENT
        pygame.draw.circle(self.screen, clr, (self.fc_x, self.fc_y), r)
        pygame.draw.circle(self.screen, Config.WHITE, (self.fc_x, self.fc_y), r, 2)
        txt = self.f_small.render("CLICK!", True, Config.BG)
        if self.fc_r > self.fc_max * 0.7:
            self.screen.blit(txt, (self.fc_x - txt.get_width()//2,
                                   self.fc_y - txt.get_height()//2))

    def _draw_pencil(self):
        cx, cy = 683, 384
        # رسم القلم (خط عمودي)
        scale = 0.3 + self.pc_z * 0.7
        length = int(200 * scale)
        width  = max(3, int(12 * scale))
        pygame.draw.rect(self.screen, (200, 180, 100),
                         (cx - width//2, cy - length//2, width, length),
                         border_radius=4)
        # نقطة في المنتصف
        pygame.draw.circle(self.screen, Config.RED, (cx, cy), 8)
        # مسافة
        dist_txt = "CLOSE" if self.pc_z > 0.6 else ("MEDIUM" if self.pc_z > 0.3 else "FAR")
        self.screen.blit(
            self.f_small.render(f"Distance: {dist_txt}", True, Config.YELLOW),
            (cx - 60, cy + 120)
        )


# ============================================================
# 9. التطبيق الرئيسي
# ============================================================
class App:
    def __init__(self):
        pygame.init()
        self.screen = pygame.display.set_mode((Config.W, Config.H))
        pygame.display.set_caption("OptiPath AI v4")
        self.clock  = pygame.time.Clock()

        self.fw  = Firewall()
        self.db  = Database()
        self.ai  = AIEngine(self.fw)
        self.eye = EyeAnalyzer()
        self.pdf = PDFAnalyzer()
        self.rpt = ReportGenerator()
        self.cap = cv2.VideoCapture(0)

        self.f_tiny  = pygame.font.SysFont("Arial", 14)
        self.f_small = pygame.font.SysFont("Arial", 18)
        self.f_med   = pygame.font.SysFont("Arial", 22)
        self.f_large = pygame.font.SysFont("Arial", 32, bold=True)

        fonts = (self.f_tiny, self.f_small, self.f_med, self.f_large)
        self.ex = ExerciseEngine(self.screen, fonts)

        self.state        = "LOGIN"
        self.doctor_name  = ""
        self.active_input = None
        self.is_loading   = False
        self.status_msg   = ""
        self.error_color  = Config.RED

        self._plan_lock     = threading.Lock()
        self.generated_plan = ""
        self.current_exam_risks = (0, 0)
        self._live_risk_l = 0
        self._live_risk_r = 0

        self.pdf_path    = ""
        self.pdf_text    = ""
        self.pdf_risk_l  = 0
        self.pdf_risk_r  = 0
        self.exam_source = "camera"

        self.forms = {
            "login":    {"email": "", "pwd": ""},
            "register": {"name": "", "email": "", "pwd": ""},
            "patient":  {"name": "", "age": ""}
        }

        # للرسم البياني
        self._progress_data = []

    # ─── مساعدات الرسم ────────────────────────────────────────
    def draw_input(self, label, x, y, w, h, val, fid, secret=False):
        self.screen.blit(self.f_small.render(label, True, (160,160,160)), (x, y-25))
        clr = Config.ACCENT if self.active_input == fid else (50,60,80)
        pygame.draw.rect(self.screen, Config.INPUT_BG, (x,y,w,h), border_radius=10)
        pygame.draw.rect(self.screen, clr, (x,y,w,h), 2, border_radius=10)
        disp = "*" * len(val) if secret else val
        self.screen.blit(self.f_med.render(disp[-30:], True, Config.WHITE), (x+15, y+12))

    def draw_button(self, x, y, w, h, clr, label, font=None):
        font = font or self.f_small
        pygame.draw.rect(self.screen, clr, (x,y,w,h), border_radius=12)
        s = font.render(label, True, Config.BG)
        self.screen.blit(s, (x+(w-s.get_width())//2, y+(h-s.get_height())//2))

    def render_sidebar(self):
        pygame.draw.rect(self.screen, Config.SIDEBAR_COLOR, (0,0,280,Config.H))
        self.screen.blit(self.f_large.render("OPTIPATH", True, Config.ACCENT), (45,50))

        fw_clr = Config.GREEN if self.fw.blocked_count == 0 else Config.YELLOW
        pygame.draw.rect(self.screen, (15,30,50), (20,95,240,35), border_radius=8)
        self.screen.blit(
            self.f_tiny.render(f"Shield Firewall ON | Blocked: {self.fw.blocked_count}",
                               True, fw_clr), (35,105))

        pages = [("DASHBOARD","Dashboard"), ("EXAM","New Exam"),
                 ("EXERCISES","Exercises"), ("PLAN","Treatment Plan"),
                 ("RECORDS","Records")]
        for i, (pid, lbl) in enumerate(pages):
            active = self.state == pid
            if active:
                pygame.draw.rect(self.screen, (35,55,90), (20,150+i*55,240,42), border_radius=10)
            clr = Config.ACCENT if active else (180,180,180)
            self.screen.blit(self.f_small.render(lbl, True, clr), (45,160+i*55))

        pygame.draw.rect(self.screen, (40,20,30), (20,680,240,45), border_radius=10)
        self.screen.blit(self.f_small.render("Logout", True, Config.RED), (105,690))

    # ─── Callbacks ────────────────────────────────────────────
    def _on_ai_ready(self, txt):
        with self._plan_lock:
            self.generated_plan = txt
        self.is_loading = False
        self.state = "PLAN"

    # ─── Keyboard ─────────────────────────────────────────────
    def _handle_keydown(self, ev):
        if not self.active_input:
            return
        prefix, key = self.active_input.split('_', 1)
        form = {'l':'login','r':'register','p':'patient'}.get(prefix)
        if not form:
            return
        if ev.key == pygame.K_BACKSPACE:
            self.forms[form][key] = self.forms[form][key][:-1]
        elif ev.key == pygame.K_RETURN:
            self.active_input = None
        elif ev.unicode.isprintable():
            if len(self.forms[form][key]) < Config.MAX_INPUT_LEN:
                self.forms[form][key] += ev.unicode

    # ─── الحلقة الرئيسية ──────────────────────────────────────
    def run(self):
        try:
            self._main_loop()
        finally:
            self.cap.release()
            pygame.quit()

    def _main_loop(self):
        running = True
        while running:
            self.screen.fill(Config.BG)

            # تحديث التمرين
            if self.ex.active:
                self.ex.update()
                if self.ex.finished():
                    # احفظ الجلسة
                    self.db.save_session(
                        self.forms["patient"]["name"],
                        self.ex.ex_type,
                        int(self.ex.elapsed()),
                        self.ex.score
                    )
                    self.ex.stop()
                    self.status_msg  = f"Session done! Score: {self.ex.score}"
                    self.error_color = Config.GREEN

            for ev in pygame.event.get():
                if ev.type == pygame.QUIT:
                    running = False
                if ev.type == pygame.MOUSEBUTTONDOWN:
                    self.active_input = None
                    mx, my = ev.pos
                    if self.ex.active:
                        self.ex.handle_click(mx, my)
                    else:
                        self._handle_click(mx, my)
                if ev.type == pygame.KEYDOWN:
                    self._handle_keydown(ev)

            if   self.state == "LOGIN":    self._render_login()
            elif self.state == "REGISTER": self._render_register()
            elif self.doctor_name:
                if self.ex.active:
                    self.render_sidebar()
                    self.ex.draw()
                    # زر إيقاف
                    self.draw_button(340, Config.H-55, 160, 40,
                                     Config.RED, "STOP EXERCISE")
                else:
                    self.render_sidebar()
                    if   self.state == "DASHBOARD": self._render_dashboard()
                    elif self.state == "EXAM":      self._render_exam()
                    elif self.state == "EXERCISES": self._render_exercises()
                    elif self.state == "PLAN":      self._render_plan()
                    elif self.state == "RECORDS":   self._render_records()

            pygame.display.flip()
            self.clock.tick(30)

    # ─── النقرات ──────────────────────────────────────────────
    def _handle_click(self, mx, my):
        if self.state == "LOGIN":
            if 480 < mx < 880:
                if   280 < my < 330: self.active_input = "l_email"
                elif 380 < my < 430: self.active_input = "l_pwd"
            if 480 < mx < 880 and 480 < my < 535:
                res = self.db.verify_doctor(self.forms["login"]["email"],
                                            self.forms["login"]["pwd"])
                if res:
                    self.doctor_name = res; self.state = "DASHBOARD"; self.status_msg = ""
                else:
                    self.status_msg = "Error: Invalid Credentials"; self.error_color = Config.RED
            if 480 < mx < 880 and 550 < my < 580:
                self.state = "REGISTER"; self.status_msg = ""

        elif self.state == "REGISTER":
            if 480 < mx < 880:
                if   200 < my < 250: self.active_input = "r_name"
                elif 300 < my < 350: self.active_input = "r_email"
                elif 400 < my < 450: self.active_input = "r_pwd"
            if 480 < mx < 880 and 500 < my < 555:
                reg = self.db.register_doctor(self.forms["register"]["name"],
                                              self.forms["register"]["email"],
                                              self.forms["register"]["pwd"])
                if reg is True:
                    self.status_msg = "Account Created! Please Login."
                    self.error_color = Config.GREEN; self.state = "LOGIN"
                elif reg == "exists":
                    self.status_msg = "Error: Email already registered"; self.error_color = Config.RED
                elif reg == "empty":
                    self.status_msg = "Error: All fields required"; self.error_color = Config.RED
                else:
                    self.status_msg = "Error: Could not save"; self.error_color = Config.RED
            if 480 < mx < 880 and 570 < my < 600:
                self.state = "LOGIN"; self.status_msg = ""

        elif self.doctor_name:
            # Sidebar
            if mx < 280:
                if 680 < my < 725:
                    self.doctor_name = ""; self.state = "LOGIN"; self.status_msg = ""
                else:
                    idx   = (my - 150) // 55
                    pages = ["DASHBOARD","EXAM","EXERCISES","PLAN","RECORDS"]
                    if 0 <= idx < len(pages):
                        self.state = pages[idx]; self.status_msg = ""

            # زر إيقاف التمرين
            if self.ex.active and 340 < mx < 500 and Config.H-55 < my < Config.H-15:
                self.db.save_session(self.forms["patient"]["name"], self.ex.ex_type,
                                     int(self.ex.elapsed()), self.ex.score)
                self.ex.stop()
                self.status_msg  = f"Session stopped. Score: {self.ex.score}"
                self.error_color = Config.YELLOW

            # EXAM
            if self.state == "EXAM":
                if 850 < mx < 1250:
                    if   490 < my < 540: self.active_input = "p_name"
                    elif 570 < my < 620: self.active_input = "p_age"
                if 850 < mx < 1040 and 640 < my < 680:
                    self.exam_source = "camera"; self.pdf_path = ""; self.pdf_text = ""
                    self.status_msg = "Camera mode active"; self.error_color = Config.ACCENT
                if 1050 < mx < 1250 and 640 < my < 680:
                    path = self.pdf.open_file_dialog()
                    if path:
                        text, err = self.pdf.extract_text(path)
                        if err:
                            self.status_msg = f"PDF Error: {err}"; self.error_color = Config.RED
                        else:
                            self.pdf_path = path; self.pdf_text = text
                            self.pdf_risk_l, self.pdf_risk_r = self.pdf.parse_risks_from_text(text)
                            self.exam_source = "pdf"
                            self.status_msg = f"PDF: {os.path.basename(path)[:25]}"
                            self.error_color = Config.GREEN
                if 850 < mx < 1250 and 695 < my < 750 and not self.is_loading:
                    name = self.forms["patient"]["name"].strip()
                    age  = self.forms["patient"]["age"].strip()
                    if name and age:
                        self.is_loading = True
                        rl, rr = (self.pdf_risk_l, self.pdf_risk_r) if self.exam_source=="pdf" \
                                 else (self._live_risk_l, self._live_risk_r)
                        ctx    = self.pdf_text if self.exam_source=="pdf" else ""
                        self.current_exam_risks = (rl, rr)
                        self.ai.generate_plan(name, age, rl, rr, self._on_ai_ready, ctx)
                    else:
                        self.status_msg = "Error: Fill all fields"; self.error_color = Config.RED

            # EXERCISES — أزرار بدء التمارين
            if self.state == "EXERCISES":
                # زر كل تمرين
                ex_positions = [(340,270),(340,380),(340,490)]
                for i, (ex_x, ex_y) in enumerate(ex_positions):
                    if ex_x < mx < ex_x+900 and ex_y < my < ex_y+80:
                        ex_name = ExerciseEngine.EXERCISES[i]
                        self.ex.start(ex_name, duration=60)

            # PLAN
            if self.state == "PLAN" and not self.is_loading:
                if 900 < mx < 1150 and 650 < my < 705:
                    with self._plan_lock:
                        plan_text = self.generated_plan
                    ok = self.db.save_patient(
                        self.forms["patient"]["name"], self.forms["patient"]["age"],
                        self.current_exam_risks[0], self.current_exam_risks[1],
                        plan_text, self.exam_source
                    )
                    if ok:
                        self.status_msg = "Saved!"; self.error_color = Config.GREEN
                    else:
                        self.status_msg = "Error: DB Busy"; self.error_color = Config.RED

                # زر PDF
                if 1160 < mx < 1340 and 650 < my < 705:
                    with self._plan_lock:
                        plan_text = self.generated_plan
                    sessions = self.db.get_sessions(self.forms["patient"]["name"])
                    path = self.rpt.save_dialog()
                    if path:
                        ok, msg = self.rpt.generate(
                            self.forms["patient"]["name"],
                            self.forms["patient"]["age"],
                            self.current_exam_risks[0],
                            self.current_exam_risks[1],
                            plan_text, sessions, path
                        )
                        self.status_msg  = f"PDF saved!" if ok else f"PDF Error: {msg}"
                        self.error_color = Config.GREEN if ok else Config.RED

    # ─── شاشات ────────────────────────────────────────────────
    def _render_login(self):
        self.screen.blit(self.f_large.render("Doctor Login", True, Config.WHITE), (550,180))
        self.draw_input("Clinic Email", 480,280,400,50, self.forms["login"]["email"], "l_email")
        self.draw_input("Password",     480,380,400,50, self.forms["login"]["pwd"],   "l_pwd", True)
        self.draw_button(480,480,400,55, Config.ACCENT, "SIGN IN", self.f_med)
        self.screen.blit(self.f_tiny.render("No account? Register here",True,(150,150,150)),(590,555))
        if self.status_msg:
            m = self.f_small.render(self.status_msg, True, self.error_color)
            self.screen.blit(m, (Config.W//2 - m.get_width()//2, 610))

    def _render_register(self):
        self.screen.blit(self.f_large.render("Create Account", True, Config.WHITE), (530,100))
        self.draw_input("Full Name",    480,200,400,50, self.forms["register"]["name"],  "r_name")
        self.draw_input("Email",        480,300,400,50, self.forms["register"]["email"], "r_email")
        self.draw_input("Set Password", 480,400,400,50, self.forms["register"]["pwd"],   "r_pwd", True)
        self.draw_button(480,500,400,55, Config.GREEN, "REGISTER NOW", self.f_med)
        self.screen.blit(self.f_tiny.render("Already have account? Login",True,(150,150,150)),(580,575))
        if self.status_msg:
            m = self.f_small.render(self.status_msg, True, self.error_color)
            self.screen.blit(m, (Config.W//2 - m.get_width()//2, 630))

    def _render_dashboard(self):
        self.screen.blit(self.f_large.render(f"Dr. {self.doctor_name}", True, Config.WHITE), (320,50))

        # بطاقة النشاط
        pygame.draw.rect(self.screen, Config.CARD_BG, (320,130,350,200), border_radius=20)
        self.screen.blit(self.f_med.render("Clinical Activity", True, Config.ACCENT), (345,155))
        self.screen.blit(self.f_small.render(f"Total Patients: {len(self.db.get_records())}",
                                              True, Config.WHITE), (345,200))
        api_ok  = bool(Config.API_KEY)
        self.screen.blit(self.f_small.render(
            f"AI Server: {'ONLINE' if api_ok else 'NO KEY'}",
            True, Config.GREEN if api_ok else Config.RED), (345,240))

        # بطاقة Firewall
        pygame.draw.rect(self.screen, Config.CARD_BG, (690,130,350,200), border_radius=20)
        self.screen.blit(self.f_med.render("Firewall Status", True, Config.ACCENT), (715,155))
        self.screen.blit(self.f_small.render("Status: ACTIVE", True, Config.GREEN), (715,200))
        self.screen.blit(self.f_small.render(
            f"Blocked: {self.fw.blocked_count}  |  Limit: {Config.RATE_LIMIT_PER_MIN}/min",
            True, Config.WHITE), (715,240))
        self.screen.blit(self.f_tiny.render("Log: firewall_audit.log",True,(120,120,120)),(715,275))

        # بطاقة التمارين
        pygame.draw.rect(self.screen, Config.CARD_BG, (1060,130,270,200), border_radius=20)
        self.screen.blit(self.f_med.render("Exercises", True, Config.ACCENT), (1085,155))
        self.screen.blit(self.f_small.render("3 Interactive Types", True, Config.WHITE), (1085,200))
        self.draw_button(1085,250,200,40, Config.ACCENT, "GO TO EXERCISES")

    def _render_exam(self):
        self.screen.blit(self.f_large.render("AI Vision Examination", True, Config.WHITE), (320,20))
        ret, frame = self.cap.read()
        if ret:
            frame = cv2.flip(frame, 1)
            self._live_risk_l, self._live_risk_r, ann = self.eye.analyze(frame)
            f_rgb = cv2.cvtColor(cv2.resize(ann, (480,360)), cv2.COLOR_BGR2RGB)
            surf  = pygame.surfarray.make_surface(np.rot90(f_rgb))
            self.screen.blit(surf, (320,75))
        else:
            pygame.draw.rect(self.screen, Config.CARD_BG, (320,75,480,360), border_radius=10)
            self.screen.blit(self.f_small.render("Camera Unavailable",True,(100,100,100)),(480,250))

        pygame.draw.rect(self.screen, Config.CARD_BG, (320,442,480,38), border_radius=8)
        self.screen.blit(self.f_small.render(
            f"Live Risk — L:{self._live_risk_l}%  R:{self._live_risk_r}%",
            True, Config.ACCENT), (335,452))

        self.draw_input("Patient Name", 840,490,430,50, self.forms["patient"]["name"], "p_name")
        self.draw_input("Age",          840,570,150,50, self.forms["patient"]["age"],  "p_age")

        cam_clr = Config.ACCENT if self.exam_source=="camera" else (50,60,80)
        pdf_clr = Config.YELLOW if self.exam_source=="pdf"    else (50,60,80)
        self.draw_button(840,640,185,40,  cam_clr, "USE CAMERA")
        self.draw_button(1040,640,195,40, pdf_clr, "UPLOAD PDF")

        if self.pdf_path:
            pygame.draw.rect(self.screen,(15,35,25),(840,686,430,30),border_radius=6)
            self.screen.blit(self.f_tiny.render(
                f"PDF: {os.path.basename(self.pdf_path)[:25]} | L:{self.pdf_risk_l}% R:{self.pdf_risk_r}%",
                True, Config.GREEN), (850,694))

        btn_clr = (50,80,80) if self.is_loading else Config.ACCENT
        self.draw_button(840,695,430,50, btn_clr,
                         "GENERATING..." if self.is_loading else "ANALYZE & GENERATE PLAN")
        if self.status_msg:
            self.screen.blit(self.f_tiny.render(self.status_msg,True,self.error_color),(840,752))

    def _render_exercises(self):
        self.screen.blit(self.f_large.render("Interactive Eye Exercises", True, Config.WHITE), (320,25))

        exercises = [
            ("TRACKING",
             "Tracking Exercise",
             "Follow the moving ball with your weak eye only. Improves eye muscle control.",
             Config.ACCENT),
            ("FOCUS",
             "Focus Exercise",
             "Click the circle when it reaches maximum size. Trains focus and reaction.",
             Config.GREEN),
            ("PENCIL",
             "Pencil Push-up",
             "Keep eyes focused on the dot as it moves near and far. Classic amblyopia therapy.",
             Config.YELLOW),
        ]

        for i, (ex_id, title, desc, clr) in enumerate(exercises):
            y = 180 + i * 150
            pygame.draw.rect(self.screen, Config.CARD_BG, (340, y, 900, 120), border_radius=15)
            pygame.draw.rect(self.screen, clr, (340, y, 6, 120), border_radius=3)
            self.screen.blit(self.f_med.render(title, True, clr), (365, y+15))
            self.screen.blit(self.f_small.render(desc, True, (180,180,180)), (365, y+50))
            self.draw_button(1080, y+35, 150, 45, clr, "START 60s")

        # سجل الجلسات الأخيرة
        if self.forms["patient"]["name"]:
            sessions = self.db.get_sessions(self.forms["patient"]["name"])
            if sessions:
                pygame.draw.rect(self.screen, Config.CARD_BG, (340,640,900,100), border_radius=15)
                self.screen.blit(self.f_small.render("Recent Sessions:", True, Config.ACCENT), (360,655))
                for j, s in enumerate(sessions[:4]):
                    txt = f"{s['exercise']}  {s['duration']}s  Score:{s['score']}  {s['date']}"
                    self.screen.blit(self.f_tiny.render(txt,True,Config.WHITE),(360, 685+j*18))

        if self.status_msg:
            self.screen.blit(self.f_small.render(self.status_msg,True,self.error_color),(340,760))

    def _render_plan(self):
        self.screen.blit(self.f_large.render("Patient Treatment Strategy",True,Config.WHITE),(320,20))
        src = "PDF Report" if self.exam_source=="pdf" else "Camera"
        pygame.draw.rect(self.screen, Config.CARD_BG, (320,65,1000,560), border_radius=20)
        self.screen.blit(self.f_small.render(
            f"Patient: {self.forms['patient']['name']}  |  "
            f"L {self.current_exam_risks[0]}% — R {self.current_exam_risks[1]}%  |  {src}",
            True, Config.ACCENT), (345,90))

        with self._plan_lock:
            plan_text = self.generated_plan

        if self.is_loading:
            self.screen.blit(self.f_med.render("Generating AI plan...",True,Config.WHITE),(430,320))
        else:
            lines = plan_text.split('\n')
            for i, line in enumerate(lines[:22]):
                self.screen.blit(self.f_tiny.render(line[:118],True,Config.WHITE),
                                 (345, 135 + i*22))

        self.draw_button(900,650,250,50, Config.GREEN, "SAVE TO RECORDS")
        self.draw_button(1160,650,175,50, Config.ORANGE, "EXPORT PDF")
        if self.status_msg:
            self.screen.blit(self.f_small.render(self.status_msg,True,self.error_color),(320,658))

    def _render_records(self):
        self.screen.blit(self.f_large.render("Medical History",True,Config.WHITE),(320,20))
        records = self.db.get_records()

        # ── الجدول ────────────────────────────────────────────
        pygame.draw.rect(self.screen, Config.CARD_BG, (320,70,700,660), border_radius=15)
        headers = ["Name","Age","L-Risk","R-Risk","Date","Src"]
        col_x   = [335,490,570,650,730,870]
        for i,h in enumerate(headers):
            self.screen.blit(self.f_small.render(h,True,Config.ACCENT),(col_x[i],90))
        for ri, row in enumerate(records[:16]):
            for ci, val in enumerate(row[:6]):
                clr = Config.YELLOW if ci==5 and str(val)=="pdf" else Config.WHITE
                self.screen.blit(self.f_tiny.render(str(val)[:14],True,clr),
                                 (col_x[ci], 135+ri*32))

        # ── الرسم البياني للتقدم ───────────────────────────────
        pygame.draw.rect(self.screen, Config.CARD_BG, (1040,70,300,400), border_radius=15)
        self.screen.blit(self.f_small.render("Risk Progress",True,Config.ACCENT),(1060,90))

        if len(records) >= 2:
            chart_x, chart_y = 1055, 120
            chart_w, chart_h = 270, 300
            pygame.draw.rect(self.screen,(10,20,40),(chart_x,chart_y,chart_w,chart_h))

            # محاور
            pygame.draw.line(self.screen,(60,70,90),(chart_x,chart_y),(chart_x,chart_y+chart_h),1)
            pygame.draw.line(self.screen,(60,70,90),
                             (chart_x,chart_y+chart_h),(chart_x+chart_w,chart_y+chart_h),1)

            pts_l = []
            pts_r = []
            data  = list(reversed(records[-10:]))
            for i, row in enumerate(data):
                x = chart_x + int(i / max(len(data)-1,1) * chart_w)
                yl = chart_y + chart_h - int(row[2] / 100 * chart_h)
                yr = chart_y + chart_h - int(row[3] / 100 * chart_h)
                pts_l.append((x, yl))
                pts_r.append((x, yr))

            if len(pts_l) >= 2:
                pygame.draw.lines(self.screen, Config.ACCENT, False, pts_l, 2)
                pygame.draw.lines(self.screen, Config.GREEN,  False, pts_r, 2)
            for p in pts_l:
                pygame.draw.circle(self.screen, Config.ACCENT, p, 4)
            for p in pts_r:
                pygame.draw.circle(self.screen, Config.GREEN,  p, 4)

            # Legend
            pygame.draw.rect(self.screen, Config.ACCENT, (1060, 435, 12, 12))
            self.screen.blit(self.f_tiny.render("Left Eye",  True, Config.WHITE), (1078,435))
            pygame.draw.rect(self.screen, Config.GREEN,  (1150, 435, 12, 12))
            self.screen.blit(self.f_tiny.render("Right Eye", True, Config.WHITE), (1168,435))
        else:
            self.screen.blit(
                self.f_tiny.render("Need 2+ records for chart",True,(120,120,120)),
                (1060,250)
            )


# ============================================================
# نقطة الدخول
# ============================================================
if __name__ == "__main__":
    App().run()
