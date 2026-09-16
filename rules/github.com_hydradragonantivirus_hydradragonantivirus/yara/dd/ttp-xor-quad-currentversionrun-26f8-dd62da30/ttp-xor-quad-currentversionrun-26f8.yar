rule TTP_XOR_QUAD_CurrentVersionRun_26f8 {
  strings:
    $key_26f8 = { 75 97 [2] 51 99 [2] 7a b5 [2] 54 97 [2] 40 8c [2] 4f 96 [2] 51 8b [2] 53 8a [2] 48 8c [2] 54 8b [2] 48 a4 }

  condition:
    any of them
}