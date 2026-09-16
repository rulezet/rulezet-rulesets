rule TTP_XOR_QUAD_CurrentVersionRun_3b04 {
  strings:
    $key_3b04 = { 68 6b [2] 4c 65 [2] 67 49 [2] 49 6b [2] 5d 70 [2] 52 6a [2] 4c 77 [2] 4e 76 [2] 55 70 [2] 49 77 [2] 55 58 }

  condition:
    any of them
}