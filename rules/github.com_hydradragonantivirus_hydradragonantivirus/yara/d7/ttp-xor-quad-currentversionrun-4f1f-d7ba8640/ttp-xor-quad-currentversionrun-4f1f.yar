rule TTP_XOR_QUAD_CurrentVersionRun_4f1f {
  strings:
    $key_4f1f = { 1c 70 [2] 38 7e [2] 13 52 [2] 3d 70 [2] 29 6b [2] 26 71 [2] 38 6c [2] 3a 6d [2] 21 6b [2] 3d 6c [2] 21 43 }

  condition:
    any of them
}