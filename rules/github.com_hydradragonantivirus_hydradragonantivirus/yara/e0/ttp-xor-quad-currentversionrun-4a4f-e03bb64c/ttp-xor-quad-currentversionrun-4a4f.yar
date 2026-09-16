rule TTP_XOR_QUAD_CurrentVersionRun_4a4f {
  strings:
    $key_4a4f = { 19 20 [2] 3d 2e [2] 16 02 [2] 38 20 [2] 2c 3b [2] 23 21 [2] 3d 3c [2] 3f 3d [2] 24 3b [2] 38 3c [2] 24 13 }

  condition:
    any of them
}