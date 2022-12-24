"""Constants"""
from typing import List, Literal

HashSize = Literal[1, 256, 384, 512]

SIZES: List[HashSize] = [512, 384, 256, 1]

Register = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                   18, 19, 20, 21, 22, 23]
