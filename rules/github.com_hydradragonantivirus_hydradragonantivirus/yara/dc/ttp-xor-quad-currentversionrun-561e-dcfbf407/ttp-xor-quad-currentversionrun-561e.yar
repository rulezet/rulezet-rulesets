rule TTP_XOR_QUAD_CurrentVersionRun_561e {
  strings:
    $key_561e = { 05 71 [2] 21 7f [2] 0a 53 [2] 24 71 [2] 30 6a [2] 3f 70 [2] 21 6d [2] 23 6c [2] 38 6a [2] 24 6d [2] 38 42 }

  condition:
    any of them
}