rule TTP_XOR_QUAD_CurrentVersionRun_f874 {
  strings:
    $key_f874 = { ab 1b [2] 8f 15 [2] a4 39 [2] 8a 1b [2] 9e 00 [2] 91 1a [2] 8f 07 [2] 8d 06 [2] 96 00 [2] 8a 07 [2] 96 28 }

  condition:
    any of them
}