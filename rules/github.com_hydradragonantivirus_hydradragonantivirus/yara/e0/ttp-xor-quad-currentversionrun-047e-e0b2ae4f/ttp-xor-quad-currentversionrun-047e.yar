rule TTP_XOR_QUAD_CurrentVersionRun_047e {
  strings:
    $key_047e = { 57 11 [2] 73 1f [2] 58 33 [2] 76 11 [2] 62 0a [2] 6d 10 [2] 73 0d [2] 71 0c [2] 6a 0a [2] 76 0d [2] 6a 22 }

  condition:
    any of them
}