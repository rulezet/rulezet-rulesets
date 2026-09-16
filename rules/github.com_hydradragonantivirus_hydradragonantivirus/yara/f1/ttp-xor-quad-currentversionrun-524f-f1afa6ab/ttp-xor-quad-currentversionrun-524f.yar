rule TTP_XOR_QUAD_CurrentVersionRun_524f {
  strings:
    $key_524f = { 01 20 [2] 25 2e [2] 0e 02 [2] 20 20 [2] 34 3b [2] 3b 21 [2] 25 3c [2] 27 3d [2] 3c 3b [2] 20 3c [2] 3c 13 }

  condition:
    any of them
}