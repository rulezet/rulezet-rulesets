rule libdjvu_IW44_norm_of_all_wavelets__flt32___32_lil_64_ {
  strings:
    $a0 = { d3 3f 24 45 10 4a 37 43 c0 4b 37 43 6d 96 4c 42 71 55 37 42 a7 56 37 42 0e ad 4c 41 86 f2 37 41 34 f4 37 41 43 02 4e 40 38 f4 3f 40 6a f7 3f 40 a5 91 5f 3f 9c 87 89 3f 94 89 89 3f f3 9c db 3e }

  condition:
    $a0
}