# VulneraX

أداة متكاملة للزحف واكتشاف الثغرات في تطبيقات الويب (Recon & Vulnerability Scanner)

---

## المميزات
- زحف تلقائي لاكتشاف السبدومينات، الروابط، والبراميترز.
- تجربة جميع أنواع الهجمات (XSS, SQLi, SSRF, ... إلخ) على كل براميتر.
- تجربة كل payload بثلاث طرق تشفير (مباشر، url encode، base64، جزئي).
- توليد تقرير شامل بالنتائج.
- **بدون أي بروكسي افتراضي**: كل الطلبات تذهب مباشرة للموقع المستهدف.

---

## المتطلبات
- Python 3.8+
- مكتبات: requests, beautifulsoup4

---

## طريقة التشغيل

### 1. ضع الدومين المستهدف في السكوب
```bash
echo "example.com" > data/scope.txt
```

### 2. شغل كل شيء دفعة واحدة (الطريقة الأسهل)
```bash
./run.sh --mode workflow --max-pages 30 --threads 20 --attack-types "xss,sqli,ssrf" --timeout 8
```

### 3. أو شغل كل مرحلة على حدة
#### (أ) الزحف (Recon):
```bash
./run.sh --mode recon --max-pages 30 --threads 20
```
#### (ب) الفحص (Scan):
```bash
./run.sh --mode scan --attack-types "xss,sqli,ssrf" --threads 20 --timeout 8
```
#### (ج) توليد التقرير:
```bash
./run.sh --mode report
# أو مباشرة:
python3 report_generator.py
```

---

## خيارات مهمة
- `--max-pages`: عدد الصفحات التي يتم زحفها لكل دومين (زدها للمواقع الكبيرة)
- `--threads`: عدد الـ threads (20-30 جيد لمعظم الأجهزة)
- `--attack-types`: أنواع الهجمات (مثال: "xss,sqli,ssrf")
- `--timeout`: مهلة الانتظار لكل طلب (يفضل 8-10 ثواني)

---

## أين تجد النتائج؟
- نتائج الزحف: `data/recon_full.json`
- روابط الفحص: `data/scan_targets.txt`
- نتائج الفحص: `agent/scan_results.jsonl`
- التقرير النهائي: `vulnerability_report.txt`

---

## ملاحظات
- لا يوجد أي بروكسي افتراضي، كل الطلبات تذهب مباشرة للموقع.
- إذا أردت تخصيص الـ payloads، عدل الملفات في مجلد `payloads/`.
- إذا واجهت أي مشكلة أو أردت تخصيص الأداة أكثر، تواصل مع المطور أو افتح issue.

---

بالتوفيق في الصيد! 🕵️‍♂️
