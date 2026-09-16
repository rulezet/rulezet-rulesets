rule TTP_XOR_QUAD_CurrentVersionRun_541e {
  strings:
    $key_541e = { 07 71 [2] 23 7f [2] 08 53 [2] 26 71 [2] 32 6a [2] 3d 70 [2] 23 6d [2] 21 6c [2] 3a 6a [2] 26 6d [2] 3a 42 }

  condition:
    any of them
}