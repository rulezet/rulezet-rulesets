rule TTP_XOR_QUAD_CurrentVersionRun_7e4f {
  strings:
    $key_7e4f = { 2d 20 [2] 09 2e [2] 22 02 [2] 0c 20 [2] 18 3b [2] 17 21 [2] 09 3c [2] 0b 3d [2] 10 3b [2] 0c 3c [2] 10 13 }

  condition:
    any of them
}