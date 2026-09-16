rule TTP_XOR_QUAD_CurrentVersionRun_f879 {
  strings:
    $key_f879 = { ab 16 [2] 8f 18 [2] a4 34 [2] 8a 16 [2] 9e 0d [2] 91 17 [2] 8f 0a [2] 8d 0b [2] 96 0d [2] 8a 0a [2] 96 25 }

  condition:
    any of them
}