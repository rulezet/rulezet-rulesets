rule TTP_XOR_QUAD_CurrentVersionRun_5016 {
  strings:
    $key_5016 = { 03 79 [2] 27 77 [2] 0c 5b [2] 22 79 [2] 36 62 [2] 39 78 [2] 27 65 [2] 25 64 [2] 3e 62 [2] 22 65 [2] 3e 4a }

  condition:
    any of them
}