rule TTP_XOR_QUAD_CurrentVersionRun_7a16 {
  strings:
    $key_7a16 = { 29 79 [2] 0d 77 [2] 26 5b [2] 08 79 [2] 1c 62 [2] 13 78 [2] 0d 65 [2] 0f 64 [2] 14 62 [2] 08 65 [2] 14 4a }

  condition:
    any of them
}