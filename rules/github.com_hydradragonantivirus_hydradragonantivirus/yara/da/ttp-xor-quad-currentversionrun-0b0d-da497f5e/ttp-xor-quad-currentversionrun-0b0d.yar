rule TTP_XOR_QUAD_CurrentVersionRun_0b0d {
  strings:
    $key_0b0d = { 58 62 [2] 7c 6c [2] 57 40 [2] 79 62 [2] 6d 79 [2] 62 63 [2] 7c 7e [2] 7e 7f [2] 65 79 [2] 79 7e [2] 65 51 }

  condition:
    any of them
}