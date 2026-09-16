rule TTP_XOR_QUAD_CurrentVersionRun_3204 {
  strings:
    $key_3204 = { 61 6b [2] 45 65 [2] 6e 49 [2] 40 6b [2] 54 70 [2] 5b 6a [2] 45 77 [2] 47 76 [2] 5c 70 [2] 40 77 [2] 5c 58 }

  condition:
    any of them
}