rule TTP_XOR_QUAD_CurrentVersionRun_4816 {
  strings:
    $key_4816 = { 1b 79 [2] 3f 77 [2] 14 5b [2] 3a 79 [2] 2e 62 [2] 21 78 [2] 3f 65 [2] 3d 64 [2] 26 62 [2] 3a 65 [2] 26 4a }

  condition:
    any of them
}