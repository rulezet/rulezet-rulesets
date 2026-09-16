rule TTP_XOR_QUAD_CurrentVersionRun_0b6d {
  strings:
    $key_0b6d = { 58 02 [2] 7c 0c [2] 57 20 [2] 79 02 [2] 6d 19 [2] 62 03 [2] 7c 1e [2] 7e 1f [2] 65 19 [2] 79 1e [2] 65 31 }

  condition:
    any of them
}