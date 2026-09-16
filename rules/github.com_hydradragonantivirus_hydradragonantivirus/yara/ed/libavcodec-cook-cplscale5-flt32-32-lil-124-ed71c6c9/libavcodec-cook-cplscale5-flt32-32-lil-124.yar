rule libavcodec_COOK_cplscale5__flt32___32_lil_124_ {
  strings:
    $a0 = { 08 f5 7e 3f f4 cd 7c 3f d1 8d 7a 3f 87 31 78 3f 4f b5 75 3f 7b 14 73 3f 27 49 70 3f b0 4b 6d 3f f0 11 6a 3f e9 8d 66 3f 57 ab 62 3f ff 4a 5e 3f 02 38 59 3f af 0a 53 3f 98 b5 4a 3f f3 04 35 3f 45 59 1c 3f 9e e7 10 3f 35 78 07 3f 91 f1 fd 3e 74 f7 ed 3e 85 89 de 3e 60 56 cf 3e b9 1c c0 3e 05 9f b0 3e a9 99 a0 3e eb b6 8f 3e 49 f3 7a 3e f6 17 52 3e 01 4a 21 3e 0e ab b8 3d }

  condition:
    $a0
}