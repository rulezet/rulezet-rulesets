rule psymodel_table1__flt32___32_big_100_ {
  strings:
    $a0 = { 41 30 d8 f2 41 27 ca eb 41 1f 33 68 41 10 65 53 41 02 f7 c7 40 e1 69 2a 40 c1 fa fb 40 a6 ee d9 40 8f a8 1c 40 77 3f cc 40 54 c6 55 40 37 1b 3b 40 1d 93 26 40 09 a7 a4 3f f0 80 b8 3f db c8 13 3f c8 d8 7f 3f ba 50 e7 3f ac d7 14 3f a2 c3 9c 3f 99 46 00 3f 91 6d 21 3f 89 fb 60 3f 84 e5 ad 3f 80 00 00 }

  condition:
    $a0
}