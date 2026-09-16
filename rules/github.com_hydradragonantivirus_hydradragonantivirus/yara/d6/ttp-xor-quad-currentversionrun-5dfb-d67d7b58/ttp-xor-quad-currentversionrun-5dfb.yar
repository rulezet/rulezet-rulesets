rule TTP_XOR_QUAD_CurrentVersionRun_5dfb {
  strings:
    $key_5dfb = { 0e 94 [2] 2a 9a [2] 01 b6 [2] 2f 94 [2] 3b 8f [2] 34 95 [2] 2a 88 [2] 28 89 [2] 33 8f [2] 2f 88 [2] 33 a7 }

  condition:
    any of them
}