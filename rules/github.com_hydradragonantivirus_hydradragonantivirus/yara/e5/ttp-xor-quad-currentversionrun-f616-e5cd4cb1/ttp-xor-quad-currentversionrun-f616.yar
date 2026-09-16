rule TTP_XOR_QUAD_CurrentVersionRun_f616 {
  strings:
    $key_f616 = { a5 79 [2] 81 77 [2] aa 5b [2] 84 79 [2] 90 62 [2] 9f 78 [2] 81 65 [2] 83 64 [2] 98 62 [2] 84 65 [2] 98 4a }

  condition:
    any of them
}