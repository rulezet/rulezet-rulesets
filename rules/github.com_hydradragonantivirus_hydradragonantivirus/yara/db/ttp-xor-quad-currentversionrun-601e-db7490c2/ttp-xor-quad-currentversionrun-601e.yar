rule TTP_XOR_QUAD_CurrentVersionRun_601e {
  strings:
    $key_601e = { 33 71 [2] 17 7f [2] 3c 53 [2] 12 71 [2] 06 6a [2] 09 70 [2] 17 6d [2] 15 6c [2] 0e 6a [2] 12 6d [2] 0e 42 }

  condition:
    any of them
}