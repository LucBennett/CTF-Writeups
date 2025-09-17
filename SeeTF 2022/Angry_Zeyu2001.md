# Angry Zeyu2001

![challenge](./images/Angry_Zeyu2001.PNG)

[Files](./Files/misc_angry_zeyu2001.zip)

This challenge was fun. We are provided with an archive of 1219 jpeg images. Each image is 10 pixels by 10 pixels. The file names follow a pattern of `a.b.jpg`, with `a` and `b` being integers. The `a` values range from 0 to 520, and are multiples of 10 (0,10,20...,510,520). The `b` values range from 0 to 220 and are also multiples of 10 (0,10,20...,210,220). The fact that each `a` value appears with all 23 possible `b` values seems to imply a kind of grid or coordinate system. If we treat the `a` and `b` values as an x and y coordinate then simply pasting the images together at the correct locations should be all we need.

#### Code

```python
from PIL import Image

new_img = Image.new('RGB', (520, 220))
for x in range(0,520+10,10):
    for y in range(0,220+10,10):
        i = Image.open("./pieces/pieces/{:0>3}.{:0>3}.jpg".format(x,y))
        new_img.paste(i,(x,y))

new_img.save('test.jpg')
```

In this case we saved the new image as `test.jpg`. Upon opening it we see:
![Result](./images/test.jpg)
