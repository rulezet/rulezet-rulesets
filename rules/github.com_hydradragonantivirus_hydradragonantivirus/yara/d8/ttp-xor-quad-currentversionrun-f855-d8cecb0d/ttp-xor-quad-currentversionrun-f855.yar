rule TTP_XOR_QUAD_CurrentVersionRun_f855 {
  strings:
    $key_f855 = { ab 3a [2] 8f 34 [2] a4 18 [2] 8a 3a [2] 9e 21 [2] 91 3b [2] 8f 26 [2] 8d 27 [2] 96 21 [2] 8a 26 [2] 96 09 }

  condition:
    any of them
}