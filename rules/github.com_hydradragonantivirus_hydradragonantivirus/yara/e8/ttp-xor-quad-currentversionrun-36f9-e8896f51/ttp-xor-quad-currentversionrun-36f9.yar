rule TTP_XOR_QUAD_CurrentVersionRun_36f9 {
  strings:
    $key_36f9 = { 65 96 [2] 41 98 [2] 6a b4 [2] 44 96 [2] 50 8d [2] 5f 97 [2] 41 8a [2] 43 8b [2] 58 8d [2] 44 8a [2] 58 a5 }

  condition:
    any of them
}