rule TTP_XOR_QUAD_CurrentVersionRun_6423 {
  strings:
    $key_6423 = { 37 4c [2] 13 42 [2] 38 6e [2] 16 4c [2] 02 57 [2] 0d 4d [2] 13 50 [2] 11 51 [2] 0a 57 [2] 16 50 [2] 0a 7f }

  condition:
    any of them
}