rule TTP_XOR_QUAD_CurrentVersionRun_215f {
  strings:
    $key_215f = { 72 30 [2] 56 3e [2] 7d 12 [2] 53 30 [2] 47 2b [2] 48 31 [2] 56 2c [2] 54 2d [2] 4f 2b [2] 53 2c [2] 4f 03 }

  condition:
    any of them
}