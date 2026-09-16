rule TTP_XOR_QUAD_CurrentVersionRun_52f8 {
  strings:
    $key_52f8 = { 01 97 [2] 25 99 [2] 0e b5 [2] 20 97 [2] 34 8c [2] 3b 96 [2] 25 8b [2] 27 8a [2] 3c 8c [2] 20 8b [2] 3c a4 }

  condition:
    any of them
}