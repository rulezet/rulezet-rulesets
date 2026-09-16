rule TTP_XOR_QUAD_CurrentVersionRun_651e {
  strings:
    $key_651e = { 36 71 [2] 12 7f [2] 39 53 [2] 17 71 [2] 03 6a [2] 0c 70 [2] 12 6d [2] 10 6c [2] 0b 6a [2] 17 6d [2] 0b 42 }

  condition:
    any of them
}