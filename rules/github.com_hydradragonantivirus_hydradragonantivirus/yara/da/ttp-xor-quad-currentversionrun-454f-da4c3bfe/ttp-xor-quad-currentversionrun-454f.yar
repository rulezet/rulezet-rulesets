rule TTP_XOR_QUAD_CurrentVersionRun_454f {
  strings:
    $key_454f = { 16 20 [2] 32 2e [2] 19 02 [2] 37 20 [2] 23 3b [2] 2c 21 [2] 32 3c [2] 30 3d [2] 2b 3b [2] 37 3c [2] 2b 13 }

  condition:
    any of them
}