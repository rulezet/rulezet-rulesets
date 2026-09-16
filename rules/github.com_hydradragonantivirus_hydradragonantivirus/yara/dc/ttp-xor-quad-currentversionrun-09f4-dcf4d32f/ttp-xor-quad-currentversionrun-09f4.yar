rule TTP_XOR_QUAD_CurrentVersionRun_09f4 {
  strings:
    $key_09f4 = { 5a 9b [2] 7e 95 [2] 55 b9 [2] 7b 9b [2] 6f 80 [2] 60 9a [2] 7e 87 [2] 7c 86 [2] 67 80 [2] 7b 87 [2] 67 a8 }

  condition:
    any of them
}