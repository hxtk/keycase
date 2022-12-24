"""Constants"""
from typing import List, Literal

HashSize = Literal[1, 256, 384, 512]

SIZES: List[HashSize] = [512, 384, 256, 1]
