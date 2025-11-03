def analyze_behavior(behavior: dict) -> float:
    typing = float(behavior.get('typing_cps') or 0.0)
    mouse = float(behavior.get('avg_mouse_speed') or 0.0)
    click_std = float(behavior.get('click_std') or 0.0)
    scroll = float(behavior.get('scroll_speed') or 0.0)
    score=0.0
    if typing==0: score+=10
    elif typing<1.0: score += 10*(1.0-typing)
    elif typing>10.0: score += 5*(typing-10.0)
    if mouse<20: score+=15
    elif mouse<80: score+=5
    if click_std<50: score+=15
    elif click_std<150: score+=5
    if scroll==0: score+=5
    elif scroll>200: score+=10
    return max(0.0, min(100.0, score))
