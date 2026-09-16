rule TTP_XOR_QUAD_CurrentVersionRun_494f {
  strings:
    $key_494f = { 1a 20 [2] 3e 2e [2] 15 02 [2] 3b 20 [2] 2f 3b [2] 20 21 [2] 3e 3c [2] 3c 3d [2] 27 3b [2] 3b 3c [2] 27 13 }

  condition:
    any of them
}