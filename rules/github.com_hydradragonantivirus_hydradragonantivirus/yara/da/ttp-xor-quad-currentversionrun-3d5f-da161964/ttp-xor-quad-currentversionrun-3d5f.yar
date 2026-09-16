rule TTP_XOR_QUAD_CurrentVersionRun_3d5f {
  strings:
    $key_3d5f = { 6e 30 [2] 4a 3e [2] 61 12 [2] 4f 30 [2] 5b 2b [2] 54 31 [2] 4a 2c [2] 48 2d [2] 53 2b [2] 4f 2c [2] 53 03 }

  condition:
    any of them
}