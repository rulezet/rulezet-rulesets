rule TTP_XOR_QUAD_CurrentVersionRun_7f4f {
  strings:
    $key_7f4f = { 2c 20 [2] 08 2e [2] 23 02 [2] 0d 20 [2] 19 3b [2] 16 21 [2] 08 3c [2] 0a 3d [2] 11 3b [2] 0d 3c [2] 11 13 }

  condition:
    any of them
}