rule TTP_XOR_QUAD_CurrentVersionRun_375f {
  strings:
    $key_375f = { 64 30 [2] 40 3e [2] 6b 12 [2] 45 30 [2] 51 2b [2] 5e 31 [2] 40 2c [2] 42 2d [2] 59 2b [2] 45 2c [2] 59 03 }

  condition:
    any of them
}