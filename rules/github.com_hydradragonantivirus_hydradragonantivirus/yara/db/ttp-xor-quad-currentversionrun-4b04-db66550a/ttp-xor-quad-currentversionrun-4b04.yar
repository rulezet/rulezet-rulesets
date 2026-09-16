rule TTP_XOR_QUAD_CurrentVersionRun_4b04 {
  strings:
    $key_4b04 = { 18 6b [2] 3c 65 [2] 17 49 [2] 39 6b [2] 2d 70 [2] 22 6a [2] 3c 77 [2] 3e 76 [2] 25 70 [2] 39 77 [2] 25 58 }

  condition:
    any of them
}