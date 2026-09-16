rule TTP_XOR_QUAD_CurrentVersionRun_247e {
  strings:
    $key_247e = { 77 11 [2] 53 1f [2] 78 33 [2] 56 11 [2] 42 0a [2] 4d 10 [2] 53 0d [2] 51 0c [2] 4a 0a [2] 56 0d [2] 4a 22 }

  condition:
    any of them
}