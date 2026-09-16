rule TTP_XOR_QUAD_CurrentVersionRun_706f {
  strings:
    $key_706f = { 23 00 [2] 07 0e [2] 2c 22 [2] 02 00 [2] 16 1b [2] 19 01 [2] 07 1c [2] 05 1d [2] 1e 1b [2] 02 1c [2] 1e 33 }

  condition:
    any of them
}