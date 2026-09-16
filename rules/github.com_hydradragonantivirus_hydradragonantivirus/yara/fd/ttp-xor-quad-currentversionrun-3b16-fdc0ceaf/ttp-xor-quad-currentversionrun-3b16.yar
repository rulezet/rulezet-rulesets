rule TTP_XOR_QUAD_CurrentVersionRun_3b16 {
  strings:
    $key_3b16 = { 68 79 [2] 4c 77 [2] 67 5b [2] 49 79 [2] 5d 62 [2] 52 78 [2] 4c 65 [2] 4e 64 [2] 55 62 [2] 49 65 [2] 55 4a }

  condition:
    any of them
}