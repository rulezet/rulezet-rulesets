rule TTP_XOR_QUAD_CurrentVersionRun_26f4 {
  strings:
    $key_26f4 = { 75 9b [2] 51 95 [2] 7a b9 [2] 54 9b [2] 40 80 [2] 4f 9a [2] 51 87 [2] 53 86 [2] 48 80 [2] 54 87 [2] 48 a8 }

  condition:
    any of them
}