rule TTP_XOR_QUAD_CurrentVersionRun_1b04 {
  strings:
    $key_1b04 = { 48 6b [2] 6c 65 [2] 47 49 [2] 69 6b [2] 7d 70 [2] 72 6a [2] 6c 77 [2] 6e 76 [2] 75 70 [2] 69 77 [2] 75 58 }

  condition:
    any of them
}