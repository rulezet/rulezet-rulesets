rule TTP_XOR_QUAD_CurrentVersionRun_0b10 {
  strings:
    $key_0b10 = { 58 7f [2] 7c 71 [2] 57 5d [2] 79 7f [2] 6d 64 [2] 62 7e [2] 7c 63 [2] 7e 62 [2] 65 64 [2] 79 63 [2] 65 4c }

  condition:
    any of them
}