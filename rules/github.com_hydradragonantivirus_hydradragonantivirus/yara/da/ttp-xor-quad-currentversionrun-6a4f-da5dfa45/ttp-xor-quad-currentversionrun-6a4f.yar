rule TTP_XOR_QUAD_CurrentVersionRun_6a4f {
  strings:
    $key_6a4f = { 39 20 [2] 1d 2e [2] 36 02 [2] 18 20 [2] 0c 3b [2] 03 21 [2] 1d 3c [2] 1f 3d [2] 04 3b [2] 18 3c [2] 04 13 }

  condition:
    any of them
}