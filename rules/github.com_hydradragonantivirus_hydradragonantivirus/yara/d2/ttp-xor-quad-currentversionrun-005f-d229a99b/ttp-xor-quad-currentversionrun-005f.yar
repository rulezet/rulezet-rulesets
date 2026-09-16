rule TTP_XOR_QUAD_CurrentVersionRun_005f {
  strings:
    $key_005f = { 53 30 [2] 77 3e [2] 5c 12 [2] 72 30 [2] 66 2b [2] 69 31 [2] 77 2c [2] 75 2d [2] 6e 2b [2] 72 2c [2] 6e 03 }

  condition:
    any of them
}