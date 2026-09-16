rule libfaad2_sa_quant__flt64___64_big_128_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3f a9 a6 b5 0b 0f 27 bb 3f c6 c2 26 80 9d 49 52 3f b2 12 d7 73 18 fc 50 3f d2 09 02 de 00 d1 b7 3f b9 78 d4 fd f3 b6 46 3f dc 96 bb 98 c7 e2 82 3f c1 e8 3e 42 5a ee 63 3f e1 fe 5c 91 d1 4e 3c 3f c9 0c b2 95 e9 e1 b1 3f e6 a7 1d e6 9a d4 2c 3f d1 5c fa ac d9 e8 3e 3f ec 85 87 93 dd 97 f6 3f d7 ac 71 0c b2 95 ea 3f f0 00 00 00 00 00 00 }

  condition:
    $a0
}