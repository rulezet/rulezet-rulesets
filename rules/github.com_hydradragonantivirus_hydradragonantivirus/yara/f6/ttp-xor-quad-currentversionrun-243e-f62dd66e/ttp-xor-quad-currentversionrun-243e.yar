rule TTP_XOR_QUAD_CurrentVersionRun_243e {
  strings:
    $key_243e = { 77 51 [2] 53 5f [2] 78 73 [2] 56 51 [2] 42 4a [2] 4d 50 [2] 53 4d [2] 51 4c [2] 4a 4a [2] 56 4d [2] 4a 62 }

  condition:
    any of them
}