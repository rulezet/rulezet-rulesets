rule TTP_XOR_QUAD_CurrentVersionRun_0716 {
  strings:
    $key_0716 = { 54 79 [2] 70 77 [2] 5b 5b [2] 75 79 [2] 61 62 [2] 6e 78 [2] 70 65 [2] 72 64 [2] 69 62 [2] 75 65 [2] 69 4a }

  condition:
    any of them
}