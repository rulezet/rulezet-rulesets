rule TTP_XOR_QUAD_CurrentVersionRun_681d {
  strings:
    $key_681d = { 3b 72 [2] 1f 7c [2] 34 50 [2] 1a 72 [2] 0e 69 [2] 01 73 [2] 1f 6e [2] 1d 6f [2] 06 69 [2] 1a 6e [2] 06 41 }

  condition:
    any of them
}