rule LD_CELP_G_728_cb_gain_sq__flt32___32_big_32_ {
  strings:
    $a0 = { 3e 88 20 00 3f 50 71 00 40 1f 96 84 40 f4 5e 7a 3e 88 20 00 3f 50 71 00 40 1f 96 84 40 f4 5e 7a }

  condition:
    $a0
}