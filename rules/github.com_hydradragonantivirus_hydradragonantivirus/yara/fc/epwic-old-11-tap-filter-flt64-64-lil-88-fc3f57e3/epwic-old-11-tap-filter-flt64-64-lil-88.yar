rule EPWIC_old_11_tap_filter__flt64___64_lil_88_ {
  strings:
    $a0 = { 89 8e f0 32 e3 5b 80 3f c1 c4 71 5f 6b 99 94 3f e4 f2 9f 31 41 ae a9 bf d7 b9 30 4c 19 cd bf bf e8 79 9c 0c e9 b2 d2 3f 2a 12 15 9d af a9 e6 3f e8 79 9c 0c e9 b2 d2 3f d7 b9 30 4c 19 cd bf bf e4 f2 9f 31 41 ae a9 bf c1 c4 71 5f 6b 99 94 3f 89 8e f0 32 e3 5b 80 3f }

  condition:
    $a0
}