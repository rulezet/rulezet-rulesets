rule TTP_XOR_QUAD_CurrentVersionRun_77e5 {
  strings:
    $key_77e5 = { 24 8a [2] 00 84 [2] 2b a8 [2] 05 8a [2] 11 91 [2] 1e 8b [2] 00 96 [2] 02 97 [2] 19 91 [2] 05 96 [2] 19 b9 }

  condition:
    any of them
}