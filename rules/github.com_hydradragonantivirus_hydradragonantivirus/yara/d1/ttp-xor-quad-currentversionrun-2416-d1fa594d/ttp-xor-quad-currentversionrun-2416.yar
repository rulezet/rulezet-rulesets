rule TTP_XOR_QUAD_CurrentVersionRun_2416 {
  strings:
    $key_2416 = { 77 79 [2] 53 77 [2] 78 5b [2] 56 79 [2] 42 62 [2] 4d 78 [2] 53 65 [2] 51 64 [2] 4a 62 [2] 56 65 [2] 4a 4a }

  condition:
    any of them
}