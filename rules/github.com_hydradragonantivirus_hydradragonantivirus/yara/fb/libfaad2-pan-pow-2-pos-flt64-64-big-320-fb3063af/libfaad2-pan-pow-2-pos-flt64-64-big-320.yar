rule libfaad2_pan_pow_2_pos__flt64___64_big_320_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f1 f3 b8 79 58 b1 72 3f f1 f3 b8 79 58 b1 72 3f f4 24 95 0a be 9f e3 3f f4 24 95 0a be 9f e3 3f f4 24 95 0a be 9f e3 3f f4 24 95 0a be 9f e3 3f f4 24 95 0a be 9f e3 3f f9 5b c9 8a 22 2d 51 3f fc 73 ec 60 e6 ca a5 3f fc 73 ec 60 e6 ca a5 3f f6 99 cc 09 58 6e 56 3f f9 5b c9 8a 22 2d 51 3f ff ec b7 68 b7 79 7e 40 06 8c 2d 78 08 4f 5a 40 09 4c 81 90 8e 58 1d 3f f9 5b c9 8a 22 2d 51 3f ff ec b7 83 8f 6c 19 40 06 8c 2d 78 08 4f 5a 40 11 de 30 29 93 77 41 40 16 7e 30 f9 9d 0f 70 3f fc 73 ec 60 e6 ca a5 40 04 18 72 29 e9 07 96 40 11 de 30 29 93 77 41 40 1f c5 b8 e3 0a fc b3 40 26 70 a3 0d b6 a1 e8 3f ff ec b7 68 b7 79 7e 40 0c 62 c7 0a 15 2c b8 40 1c 51 2b 65 08 98 55 40 2c 40 1b 00 36 86 a5 40 39 1e 6e a8 54 47 80 40 04 18 72 29 e9 07 96 40 14 0b fb 08 49 7a 9d 40 26 70 a3 0d b6 a1 e8 40 39 1e 6e a8 54 47 80 40 4c 1e 19 11 48 fd a0 }

  condition:
    $a0
}