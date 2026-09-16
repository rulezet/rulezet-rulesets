rule TTP_XOR_QUAD_CurrentVersionRun_4b16 {
  strings:
    $key_4b16 = { 18 79 [2] 3c 77 [2] 17 5b [2] 39 79 [2] 2d 62 [2] 22 78 [2] 3c 65 [2] 3e 64 [2] 25 62 [2] 39 65 [2] 25 4a }

  condition:
    any of them
}