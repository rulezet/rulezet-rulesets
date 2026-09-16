rule TTP_XOR_QUAD_CurrentVersionRun_65e5 {
  strings:
    $key_65e5 = { 36 8a [2] 12 84 [2] 39 a8 [2] 17 8a [2] 03 91 [2] 0c 8b [2] 12 96 [2] 10 97 [2] 0b 91 [2] 17 96 [2] 0b b9 }

  condition:
    any of them
}