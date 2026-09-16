rule TTP_XOR_QUAD_CurrentVersionRun_251e {
  strings:
    $key_251e = { 76 71 [2] 52 7f [2] 79 53 [2] 57 71 [2] 43 6a [2] 4c 70 [2] 52 6d [2] 50 6c [2] 4b 6a [2] 57 6d [2] 4b 42 }

  condition:
    any of them
}