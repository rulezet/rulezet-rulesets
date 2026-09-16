rule TTP_XOR_QUAD_CurrentVersionRun_451e {
  strings:
    $key_451e = { 16 71 [2] 32 7f [2] 19 53 [2] 37 71 [2] 23 6a [2] 2c 70 [2] 32 6d [2] 30 6c [2] 2b 6a [2] 37 6d [2] 2b 42 }

  condition:
    any of them
}