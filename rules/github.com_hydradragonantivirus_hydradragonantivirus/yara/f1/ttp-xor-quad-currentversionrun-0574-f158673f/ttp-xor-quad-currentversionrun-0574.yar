rule TTP_XOR_QUAD_CurrentVersionRun_0574 {
  strings:
    $key_0574 = { 56 1b [2] 72 15 [2] 59 39 [2] 77 1b [2] 63 00 [2] 6c 1a [2] 72 07 [2] 70 06 [2] 6b 00 [2] 77 07 [2] 6b 28 }

  condition:
    any of them
}