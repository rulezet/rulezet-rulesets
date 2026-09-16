rule TTP_XOR_QUAD_CurrentVersionRun_6a16 {
  strings:
    $key_6a16 = { 39 79 [2] 1d 77 [2] 36 5b [2] 18 79 [2] 0c 62 [2] 03 78 [2] 1d 65 [2] 1f 64 [2] 04 62 [2] 18 65 [2] 04 4a }

  condition:
    any of them
}