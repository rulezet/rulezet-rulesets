rule TTP_XOR_QUAD_CurrentVersionRun_1c76 {
  strings:
    $key_1c76 = { 4f 19 [2] 6b 17 [2] 40 3b [2] 6e 19 [2] 7a 02 [2] 75 18 [2] 6b 05 [2] 69 04 [2] 72 02 [2] 6e 05 [2] 72 2a }

  condition:
    any of them
}