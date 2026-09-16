rule TTP_XOR_QUAD_CurrentVersionRun_6e1e {
  strings:
    $key_6e1e = { 3d 71 [2] 19 7f [2] 32 53 [2] 1c 71 [2] 08 6a [2] 07 70 [2] 19 6d [2] 1b 6c [2] 00 6a [2] 1c 6d [2] 00 42 }

  condition:
    any of them
}