rule TTP_XOR_QUAD_CurrentVersionRun_1e5f {
  strings:
    $key_1e5f = { 4d 30 [2] 69 3e [2] 42 12 [2] 6c 30 [2] 78 2b [2] 77 31 [2] 69 2c [2] 6b 2d [2] 70 2b [2] 6c 2c [2] 70 03 }

  condition:
    any of them
}