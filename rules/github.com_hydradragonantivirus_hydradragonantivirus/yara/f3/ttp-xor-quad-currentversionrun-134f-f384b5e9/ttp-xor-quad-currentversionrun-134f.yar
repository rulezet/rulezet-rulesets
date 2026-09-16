rule TTP_XOR_QUAD_CurrentVersionRun_134f {
  strings:
    $key_134f = { 40 20 [2] 64 2e [2] 4f 02 [2] 61 20 [2] 75 3b [2] 7a 21 [2] 64 3c [2] 66 3d [2] 7d 3b [2] 61 3c [2] 7d 13 }

  condition:
    any of them
}