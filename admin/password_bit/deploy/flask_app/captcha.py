import random
import base64
import io
from PIL import Image, ImageDraw, ImageFont
import hashlib
import time

# Cache to store captcha data with expiration
captcha_cache = {}
# TTL for captcha entries (5 minutes)
CAPTCHA_TTL = 300

def generate_math_problem():
    """Generate a simple math problem."""
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    operation = random.choice(['+', '-', '*'])
    
    if operation == '+':
        answer = a + b
        problem = f"{a} + {b}"
    elif operation == '-':
        # Ensure a is greater than b to avoid negative answers
        if a < b:
            a, b = b, a
        answer = a - b
        problem = f"{a} - {b}"
    else:
        answer = a * b
        problem = f"{a} × {b}"
    
    return problem, answer

def generate_captcha_image(text, width=200, height=80):
    """Generate an image containing the captcha text."""
    image = Image.new('RGB', (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(image)
    
    # Try to use a standard font, but fallback to default if not available
    try:
        font = ImageFont.truetype("Arial", 36)
    except IOError:
        font = ImageFont.load_default()
    
    # Calculate text size to center it
    text_width = draw.textlength(text, font=font)
    text_height = 36  # Approximate height for the font
    position = ((width - text_width) // 2, (height - text_height) // 2)
    
    # Add noise (random lines)
    for _ in range(8):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=2)
    
    # Draw the text
    draw.text(position, text, font=font, fill=(33, 33, 33))
    
    # Add some dots noise
    for _ in range(500):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(0, 200), random.randint(0, 200), random.randint(0, 200)))
    
    # Convert the image to base64 for embedding in HTML
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def create_captcha():
    """Create a new captcha challenge."""
    problem, answer = generate_math_problem()
    
    # Generate a unique ID for this captcha
    captcha_id = hashlib.sha256(f"{problem}{answer}{time.time()}{random.random()}".encode()).hexdigest()
    
    # Store in cache with expiration time
    captcha_cache[captcha_id] = {
        'answer': answer,
        'expires': time.time() + CAPTCHA_TTL
    }
    
    # Generate the image
    captcha_image = generate_captcha_image(problem)
    
    return captcha_id, captcha_image

def validate_captcha(captcha_id, user_answer):
    """Validate the user's answer against the stored captcha."""
    # Clean up expired captchas
    current_time = time.time()
    expired_ids = [cid for cid, data in captcha_cache.items() if data['expires'] < current_time]
    for expired_id in expired_ids:
        captcha_cache.pop(expired_id, None)
    
    # Check if captcha exists and is valid
    if captcha_id not in captcha_cache:
        return False
    
    captcha_data = captcha_cache[captcha_id]
    
    # One-time use: remove the captcha after validation attempt
    correct_answer = captcha_data['answer']
    captcha_cache.pop(captcha_id, None)
    
    try:
        # Convert user answer to integer and compare
        return int(user_answer) == correct_answer
    except (ValueError, TypeError):
        return False
