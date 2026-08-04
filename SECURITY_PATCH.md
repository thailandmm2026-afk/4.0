# Security Hardening Patch

## ဘာလုပ်ပေးထားလဲ

1. **`security_scanner_free.py`** — အားကောင်းသော scanner (bot.py နဲ့ တူညီသော folder မှာ ထားပါ)
2. System ဖိုင်ဖတ် / ခိုးယူ / ဖောက်ထွင်း / backdoor ကို **REJECT** လုပ်ပြီး run မရအောင် ပိတ်သည်
3. User ကို **မြန်မာလို** သတိပေးသည်
4. Admin ကို အသိပေး + audit log မှတ်သည်

## ထည့်သွင်းနည်း

### အဆင့် ၁ — Scanner module ထည့်ပါ

```bash
# bot.py ရှိတဲ့ folder ထဲကို ကူးထည့်ပါ
cp security_scanner_free.py /path/to/your/bot/folder/
```

bot.py က အလိုအလျောက် import လုပ်ပြီးသား:

```python
from security_scanner_free import scan_file as _scan_file
```

### အဆင့် ၂ — User သတိပေးစာ (မြန်မာ) တိုးတက်အောင်

`_handle_bot_upload` ထဲက `if recommend == "REJECT":` block ကို အောက်ကစာသားနဲ့ အစားထိုးပါ
(သို့မဟုတ် `apply_security_patch.py` ကို run ပါ)။

### အဆင့် ၃ — Redeploy / restart bot

```bash
# သင့် hosting ပေါ်မှာ bot ကို restart
```

## စစ်ဆေးနိုင်သော ခြိမ်းခြောက်မှုများ

| အမျိုးအစား | ဥပမာ |
|---|---|
| Data Theft | `os.walk("/etc")`, `open("/etc/passwd")`, system path ကို Telegram ပို့ခြင်း |
| Backdoor | `subprocess(..., shell=True)`, `eval(compile(...))`, `os.system` |
| Path Traversal | ZIP slip (`../`, absolute paths in zip) |
| Obfuscation | base64+exec, zlib+exec, long hex payloads |
| Resource Abuse | fork bomb, massive process pools |

## ရလဒ်

- **DANGEROUS** → ဖိုင်ကို **ပိတ်**၊ sandbox ဖျက်၊ user သတိပေး၊ admin အသိပေး၊ **run မရ**
- **SUSPICIOUS** → Admin manual approve စောင့်
- **SAFE** → ပုံမှန်အတိုင်း host
