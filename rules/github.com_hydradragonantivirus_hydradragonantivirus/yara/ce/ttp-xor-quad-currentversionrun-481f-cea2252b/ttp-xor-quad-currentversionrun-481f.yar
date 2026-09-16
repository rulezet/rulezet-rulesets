rule TTP_XOR_QUAD_CurrentVersionRun_481f {
  strings:
    $key_481f = { 1b 70 [2] 3f 7e [2] 14 52 [2] 3a 70 [2] 2e 6b [2] 21 71 [2] 3f 6c [2] 3d 6d [2] 26 6b [2] 3a 6c [2] 26 43 }

  condition:
    any of them
}