rule TTP_XOR_QUAD_CurrentVersionRun_644f {
  strings:
    $key_644f = { 37 20 [2] 13 2e [2] 38 02 [2] 16 20 [2] 02 3b [2] 0d 21 [2] 13 3c [2] 11 3d [2] 0a 3b [2] 16 3c [2] 0a 13 }

  condition:
    any of them
}