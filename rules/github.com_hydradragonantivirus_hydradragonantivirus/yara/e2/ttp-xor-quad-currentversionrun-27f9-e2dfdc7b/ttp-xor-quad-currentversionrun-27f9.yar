rule TTP_XOR_QUAD_CurrentVersionRun_27f9 {
  strings:
    $key_27f9 = { 74 96 [2] 50 98 [2] 7b b4 [2] 55 96 [2] 41 8d [2] 4e 97 [2] 50 8a [2] 52 8b [2] 49 8d [2] 55 8a [2] 49 a5 }

  condition:
    any of them
}