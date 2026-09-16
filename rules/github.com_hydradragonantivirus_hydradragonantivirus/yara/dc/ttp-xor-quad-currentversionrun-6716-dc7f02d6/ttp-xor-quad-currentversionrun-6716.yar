rule TTP_XOR_QUAD_CurrentVersionRun_6716 {
  strings:
    $key_6716 = { 34 79 [2] 10 77 [2] 3b 5b [2] 15 79 [2] 01 62 [2] 0e 78 [2] 10 65 [2] 12 64 [2] 09 62 [2] 15 65 [2] 09 4a }

  condition:
    any of them
}