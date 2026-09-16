rule TTP_XOR_QUAD_CurrentVersionRun_521e {
  strings:
    $key_521e = { 01 71 [2] 25 7f [2] 0e 53 [2] 20 71 [2] 34 6a [2] 3b 70 [2] 25 6d [2] 27 6c [2] 3c 6a [2] 20 6d [2] 3c 42 }

  condition:
    any of them
}