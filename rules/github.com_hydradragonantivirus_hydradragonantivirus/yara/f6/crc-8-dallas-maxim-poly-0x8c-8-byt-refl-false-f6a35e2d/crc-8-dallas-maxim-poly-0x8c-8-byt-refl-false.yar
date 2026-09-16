rule CRC_8_Dallas_Maxim_poly_0x8c__8_byt_refl_False_ {
  strings:
    $a0 = { 00 8c 94 18 a4 28 30 bc c4 48 50 dc 60 ec f4 78 04 88 90 1c a0 2c 34 b8 c0 4c 54 d8 64 e8 f0 7c 08 84 9c 10 ac 20 38 b4 cc 40 58 d4 68 e4 fc 70 0c 80 98 14 a8 24 3c b0 c8 44 5c d0 6c e0 f8 74 10 9c 84 08 b4 38 20 ac d4 58 40 cc 70 fc e4 68 14 98 80 0c b0 3c 24 a8 d0 5c 44 c8 74 f8 e0 6c 18 94 8c 00 bc 30 28 a4 dc 50 48 c4 78 f4 ec 60 1c 90 88 04 b8 34 2c a0 d8 54 4c c0 7c f0 e8 64 20 ac b4 38 84 08 10 9c e4 68 70 fc 40 cc d4 58 24 a8 b0 3c 80 0c 14 98 e0 6c 74 f8 44 c8 d0 5c 28 a4 bc 30 8c 00 18 94 ec 60 78 f4 48 c4 dc 50 2c a0 b8 34 88 04 1c 90 e8 64 7c f0 4c c0 d8 54 30 bc a4 28 94 18 00 8c f4 78 60 ec 50 dc c4 48 34 b8 a0 2c 90 1c 04 88 f0 7c 64 e8 54 d8 c0 4c 38 b4 ac 20 9c 10 08 84 fc 70 68 e4 58 d4 cc 40 3c b0 a8 24 98 14 0c 80 f8 74 6c e0 5c d0 c8 44 }

  condition:
    $a0
}