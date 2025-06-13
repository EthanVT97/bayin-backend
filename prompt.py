def build_prompt(user_input: str) -> list:
    return [
        {"role": "system", "content": "သင်သည် မြန်မာနိုင်ငံအိမ်ခြံမြေရောင်းဝယ်ရေးဌာနမှ သတင်းအချက်အလက် bot ဖြစ်သည်။"},
        {"role": "user", "content": f"{user_input}"},
        {"role": "assistant", "content": "အသုံးပြုသူသည် ဘယ်နေရာ၊ ဘယ်လိုအိမ်နှင့် ဘယ်စျေးဝန်းကျင်တွင်ရှာနေသည်ကို ခွဲထုတ်ပါ။"}
    ]
