rule TTP_XOR_QUAD_CurrentVersionRun_264f {
  strings:
    $key_264f = { 75 20 [2] 51 2e [2] 7a 02 [2] 54 20 [2] 40 3b [2] 4f 21 [2] 51 3c [2] 53 3d [2] 48 3b [2] 54 3c [2] 48 13 }

  condition:
    any of them
}