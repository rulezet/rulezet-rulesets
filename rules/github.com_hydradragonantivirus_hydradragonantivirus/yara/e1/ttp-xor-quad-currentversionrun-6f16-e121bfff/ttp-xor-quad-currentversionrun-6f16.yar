rule TTP_XOR_QUAD_CurrentVersionRun_6f16 {
  strings:
    $key_6f16 = { 3c 79 [2] 18 77 [2] 33 5b [2] 1d 79 [2] 09 62 [2] 06 78 [2] 18 65 [2] 1a 64 [2] 01 62 [2] 1d 65 [2] 01 4a }

  condition:
    any of them
}