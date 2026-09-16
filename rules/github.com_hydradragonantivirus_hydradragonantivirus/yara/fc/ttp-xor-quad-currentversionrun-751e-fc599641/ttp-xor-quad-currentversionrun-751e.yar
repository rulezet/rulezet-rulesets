rule TTP_XOR_QUAD_CurrentVersionRun_751e {
  strings:
    $key_751e = { 26 71 [2] 02 7f [2] 29 53 [2] 07 71 [2] 13 6a [2] 1c 70 [2] 02 6d [2] 00 6c [2] 1b 6a [2] 07 6d [2] 1b 42 }

  condition:
    any of them
}