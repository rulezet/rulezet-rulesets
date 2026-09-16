rule TTP_XOR_QUAD_CurrentVersionRun_29f4 {
  strings:
    $key_29f4 = { 7a 9b [2] 5e 95 [2] 75 b9 [2] 5b 9b [2] 4f 80 [2] 40 9a [2] 5e 87 [2] 5c 86 [2] 47 80 [2] 5b 87 [2] 47 a8 }

  condition:
    any of them
}