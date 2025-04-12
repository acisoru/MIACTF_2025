import numpy as np
import cv2

def load_templates():
    templates = {
        "UP": cv2.imread("templates/arrow_up.png", cv2.IMREAD_GRAYSCALE),
        "DOWN": cv2.imread("templates/arrow_down.png", cv2.IMREAD_GRAYSCALE),
        "LEFT": cv2.imread("templates/arrow_left.png", cv2.IMREAD_GRAYSCALE),
        "RIGHT": cv2.imread("templates/arrow_right.png", cv2.IMREAD_GRAYSCALE)
    }

    for k, v in templates.items():
        if v is None:
            raise IOError(f"Could not load template for direction {k}. Check file path.")
    return templates

def multi_scale_match(template, image_gray, min_scale=0.5, max_scale=1.5, scale_steps=8):
    best_val = -1.0
    best_loc = None

    h, w = template.shape[:2]

    scales = np.linspace(min_scale, max_scale, scale_steps)

    for scale in scales:
        new_w = int(w * scale)
        new_h = int(h * scale)

        if new_w < 5 or new_h < 5:
            continue

        resized = cv2.resize(template, (new_w, new_h), interpolation=cv2.INTER_AREA)

        result = cv2.matchTemplate(image_gray, resized, cv2.TM_CCOEFF_NORMED)

        min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)

        if max_val > best_val:
            best_val = max_val
            best_loc = (max_loc, (new_w, new_h))

    return best_val, best_loc

def detect_direction(img_bgr, templates):
    image_gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

    best_overall_val = -1
    best_overall_dir = "UNKNOWN"
    best_overall_loc = None

    for direction, template_gray in templates.items():
        max_val, max_loc_info = multi_scale_match(template_gray, image_gray)
        if max_val > best_overall_val:
            best_overall_val = max_val
            best_overall_loc = max_loc_info
            best_overall_dir = direction

    return best_overall_dir, best_overall_loc