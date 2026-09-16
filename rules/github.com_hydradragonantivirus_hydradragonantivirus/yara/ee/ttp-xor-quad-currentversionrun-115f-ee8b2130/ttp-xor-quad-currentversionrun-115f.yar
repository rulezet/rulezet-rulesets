rule TTP_XOR_QUAD_CurrentVersionRun_115f {
  strings:
    $key_115f = { 42 30 [2] 66 3e [2] 4d 12 [2] 63 30 [2] 77 2b [2] 78 31 [2] 66 2c [2] 64 2d [2] 7f 2b [2] 63 2c [2] 7f 03 }

  condition:
    any of them
}