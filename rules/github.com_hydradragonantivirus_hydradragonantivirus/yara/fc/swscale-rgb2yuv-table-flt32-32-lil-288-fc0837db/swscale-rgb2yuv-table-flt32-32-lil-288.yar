rule swscale_rgb2yuv_table__flt32___32_lil_288_ {
  strings:
    $a0 = { 59 17 37 3f 98 dd 93 3d d0 b3 59 3e cb a1 c5 be 00 00 00 3f 1f 85 eb bd b0 72 e8 be 7f 6a 3c bd 00 00 00 3f 59 17 37 3f 98 dd 93 3d d0 b3 59 3e cb a1 c5 be 00 00 00 3f 1f 85 eb bd b0 72 e8 be 7f 6a 3c bd 00 00 00 3f a2 45 16 3f d5 78 e9 3d 87 16 99 3e d5 78 a9 be 00 00 00 3f 56 0e 2d be 2b 87 d6 be 54 e3 a5 bd 00 00 00 3f a2 45 16 3f d5 78 e9 3d 87 16 99 3e d5 78 a9 be 00 00 00 3f 56 0e 2d be 2b 87 d6 be 54 e3 a5 bd 00 00 00 3f 3d 0a 17 3f ae 47 e1 3d 9a 99 99 3e d5 78 a9 be 00 00 00 3f 56 0e 2d be 50 8d d7 be c1 ca a1 bd 00 00 00 3f a2 45 16 3f d5 78 e9 3d 87 16 99 3e d5 78 a9 be 00 00 00 3f 56 0e 2d be 2b 87 d6 be 54 e3 a5 bd 00 00 00 3f a2 45 16 3f d5 78 e9 3d 87 16 99 3e d5 78 a9 be 00 00 00 3f 56 0e 2d be 2b 87 d6 be 54 e3 a5 bd 00 00 00 3f bc 74 33 3f 0e 2d b2 3d 87 16 59 3e a6 9b c4 be 00 00 00 3f 68 91 ed bd 0a d7 e3 be ae 47 61 bd 00 00 00 3f }

  condition:
    $a0
}