rule TTP_XOR_QUAD_CurrentVersionRun_5b1f {
  strings:
    $key_5b1f = { 08 70 [2] 2c 7e [2] 07 52 [2] 29 70 [2] 3d 6b [2] 32 71 [2] 2c 6c [2] 2e 6d [2] 35 6b [2] 29 6c [2] 35 43 }

  condition:
    any of them
}