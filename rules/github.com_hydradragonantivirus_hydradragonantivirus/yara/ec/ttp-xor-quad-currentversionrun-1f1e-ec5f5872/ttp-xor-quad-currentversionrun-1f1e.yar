rule TTP_XOR_QUAD_CurrentVersionRun_1f1e {
  strings:
    $key_1f1e = { 4c 71 [2] 68 7f [2] 43 53 [2] 6d 71 [2] 79 6a [2] 76 70 [2] 68 6d [2] 6a 6c [2] 71 6a [2] 6d 6d [2] 71 42 }

  condition:
    any of them
}