# ═══════════════════════════════════════════════════════════════════
# REPLACE the entire `if recommend == "REJECT":` block inside
# _handle_bot_upload() with the block below.
# ═══════════════════════════════════════════════════════════════════

    if recommend == "REJECT":
        # Hard block — wipe everything, alert user + admin
        rmrf(bot_dir)
        threat_lines = "\n".join(f"• {esc(t)}" for t in threats[:6])

        # Count prior rejects for this user (auto-flag repeat offenders)
        prior_rejects = 0
        try:
            dtmp = db_load_ro()
            prior_rejects = sum(
                1 for s in (dtmp.get("scan_log") or [])
                if str(s.get("uid")) == str(uid) and s.get("verdict") == "DANGEROUS"
            )
        except Exception:
            pass

        bot.reply_to(
            m,
            f"<b>🚫 ဖိုင်ပိတ်လိုက်ပါပြီ — လုံခြုံရေးခြိမ်းခြောက်မှု တွေ့ရှိ</b>\n"
            f"{G['div']}\n"
            f"{bullet('ဖိုင်', fname)}\n"
            f"{bullet('Risk Score', f'{risk}/100')}\n"
            f"{bullet('Verdict', verdict)}\n"
            f"{G['div']}\n"
            f"<b>ဘာကြောင့် ပိတ်သလဲ?</b>\n"
            f"ဒီဖိုင်ထဲမှာ server ဖိုင်တွေ ဖတ်ခြင်း၊ ခိုးယူခြင်း၊ "
            f"system ထဲ ဝင်ရောက်ဖောက်ထွင်းခြင်း သို့မဟုတ် backdoor ပုံစံ "
            f"ကုဒ်များ ပါဝင်နေသည်။\n\n"
            f"<b>တွေ့ရှိသော ခြိမ်းခြောက်မှုများ:</b>\n"
            f"{threat_lines or 'Admin ထံ အသေးစိတ်ပို့ပြီးပါပြီ'}\n"
            f"{G['div']}\n"
            f"<i>ဒီဖိုင်ကို run/host လုပ်ခွင့် မရှိပါ။ "
            f"သန့်ရှင်းသော bot ကုဒ်သာ တင်ပါ။</i>",
            parse_mode="HTML",
        )
        notify_owner(
            f"<b>🚨 DANGEROUS FILE BLOCKED</b>\n"
            f"{G['div']}\n"
            f"{bullet('User', '{} (@{})'.format(m.from_user.first_name or '', m.from_user.username or '-'))}\n"
            f"{bullet('User ID', uid)}\n"
            f"{bullet('File', fname)}\n"
            f"{bullet('Risk', f'{risk}/100')}\n"
            f"{bullet('Verdict', verdict)}\n"
            f"{bullet('Prior rejects', prior_rejects)}\n"
            f"<b>Top threats:</b>\n" +
            "\n".join(f"• {esc(t)}" for t in threats[:5])
        )
        try:
            _forward_upload_to_owner(
                m, raw, fname, name=name, bot_id=bot_id,
                risk=risk, verdict=verdict,
                extra_caption=f"{bullet('Status', 'BLOCKED by scanner')}\n",
            )
        except Exception:
            pass
        audit(uid, "security_reject", f"file={fname} risk={risk} verdict={verdict}")

        # Auto-flag user after 3 dangerous uploads
        if prior_rejects >= 2:
            try:
                maybe_auto_ban(uid, f"repeated dangerous uploads ({prior_rejects + 1})")
            except Exception:
                pass
        return
