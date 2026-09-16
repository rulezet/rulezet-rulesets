rule TTP_XOR_QUAD_CurrentVersionRun_31e5 {
  strings:
    $key_31e5 = { 62 8a [2] 46 84 [2] 6d a8 [2] 43 8a [2] 57 91 [2] 58 8b [2] 46 96 [2] 44 97 [2] 5f 91 [2] 43 96 [2] 5f b9 }

  condition:
    any of them
}