rule libdjvu_IW44_norm_of_all_wavelets__flt64___64_big_128_ {
  strings:
    $a0 = { 40 a4 87 fa 5e 35 3f 7d 40 66 e9 41 f2 12 d7 73 40 66 e9 78 03 46 dc 5d 40 49 92 cd 9e 83 e4 26 40 46 ea ae 29 73 96 d1 40 46 ea d4 d4 02 4b 34 40 29 95 a1 ca c0 83 12 40 26 fe 50 c5 eb 31 3c 40 26 fe 86 83 3c 60 03 40 09 c0 48 5a 0b e5 11 40 07 fe 87 09 74 1d 08 40 07 fe ed 45 e9 18 5d 3f eb f2 34 9b 12 3f 9e 3f f1 30 f3 88 22 78 d1 3f f1 31 32 72 43 13 7b 3f db 73 9e 5d 4d b8 f0 }

  condition:
    $a0
}