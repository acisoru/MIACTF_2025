def generate_script(text):
    lines = text.split('\n')
    max_length = max(len(line) for line in lines)
    block_width = max(max_length + 4, 50)
    border = '#' * block_width 

    formatted_lines = []
    for line in lines:
        padding = (block_width - len(line) - 2) // 2
        formatted_line = f"# {' ' * padding}{line}{' ' * (block_width - len(line) - padding - 2)} #"
        formatted_lines.append(formatted_line)

    output = f"#!/bin/sh\necho \"\\n{border}\""
    for formatted_line in formatted_lines:
        output += f'\necho "{formatted_line}"'
    output += f'\necho "{border}"\n'

    return output

input_text = """ О нет!
Я не знаю сможешь ли ты мне помочь 
Черт, мой key manager
Черт, он поехал головой, сменил пароль 
Черт если ты мне поможшь я обещяю больше не хранить пароли там 
Черт, неееееееееееееет
я думаю для тебя нет проблемы если это 5 цифр
"""

output_script = generate_script(input_text)

with open('/tmp/banner.sh', 'w') as file:
    file.write(output_script)

print("Banner has been generated.")
