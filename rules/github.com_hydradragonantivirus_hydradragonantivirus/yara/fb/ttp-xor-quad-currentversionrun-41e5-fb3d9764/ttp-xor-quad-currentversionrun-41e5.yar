rule TTP_XOR_QUAD_CurrentVersionRun_41e5 {
  strings:
    $key_41e5 = { 12 8a [2] 36 84 [2] 1d a8 [2] 33 8a [2] 27 91 [2] 28 8b [2] 36 96 [2] 34 97 [2] 2f 91 [2] 33 96 [2] 2f b9 }

  condition:
    any of them
}