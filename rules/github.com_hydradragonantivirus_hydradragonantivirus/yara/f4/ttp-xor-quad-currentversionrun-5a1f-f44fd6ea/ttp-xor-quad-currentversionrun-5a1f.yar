rule TTP_XOR_QUAD_CurrentVersionRun_5a1f {
  strings:
    $key_5a1f = { 09 70 [2] 2d 7e [2] 06 52 [2] 28 70 [2] 3c 6b [2] 33 71 [2] 2d 6c [2] 2f 6d [2] 34 6b [2] 28 6c [2] 34 43 }

  condition:
    any of them
}