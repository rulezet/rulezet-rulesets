rule TTP_XOR_QUAD_CurrentVersionRun_4dfb {
  strings:
    $key_4dfb = { 1e 94 [2] 3a 9a [2] 11 b6 [2] 3f 94 [2] 2b 8f [2] 24 95 [2] 3a 88 [2] 38 89 [2] 23 8f [2] 3f 88 [2] 23 a7 }

  condition:
    any of them
}