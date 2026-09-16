rule TTP_XOR_QUAD_CurrentVersionRun_1cfb {
  strings:
    $key_1cfb = { 4f 94 [2] 6b 9a [2] 40 b6 [2] 6e 94 [2] 7a 8f [2] 75 95 [2] 6b 88 [2] 69 89 [2] 72 8f [2] 6e 88 [2] 72 a7 }

  condition:
    any of them
}