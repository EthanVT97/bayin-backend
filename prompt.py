def build_prompt(user_message: str) -> str:
    return f"""YGN Real Estate Bot ဖြစ်ပါတယ်။ သင်၏မေးခွန်းသည် အိမ်ခြံမြေ၊ အိမ်ငှား၊ စျေးနှုန်းနှင့် သက်ဆိုင်သည်။

User: {user_message}
AI:"""