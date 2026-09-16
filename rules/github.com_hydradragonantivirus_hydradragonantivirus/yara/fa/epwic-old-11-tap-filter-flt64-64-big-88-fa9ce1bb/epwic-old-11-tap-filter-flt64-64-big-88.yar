rule EPWIC_old_11_tap_filter__flt64___64_big_88_ {
  strings:
    $a0 = { 3f 80 5b e3 32 f0 8e 89 3f 94 99 6b 5f 71 c4 c1 bf a9 ae 41 31 9f f2 e4 bf bf cd 19 4c 30 b9 d7 3f d2 b2 e9 0c 9c 79 e8 3f e6 a9 af 9d 15 12 2a 3f d2 b2 e9 0c 9c 79 e8 bf bf cd 19 4c 30 b9 d7 bf a9 ae 41 31 9f f2 e4 3f 94 99 6b 5f 71 c4 c1 3f 80 5b e3 32 f0 8e 89 }

  condition:
    $a0
}