rule TTP_XOR_QUAD_CurrentVersionRun_1c6a {
  strings:
    $key_1c6a = { 4f 05 [2] 6b 0b [2] 40 27 [2] 6e 05 [2] 7a 1e [2] 75 04 [2] 6b 19 [2] 69 18 [2] 72 1e [2] 6e 19 [2] 72 36 }

  condition:
    any of them
}