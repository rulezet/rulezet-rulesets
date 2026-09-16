rule TTP_XOR_QUAD_CurrentVersionRun_7d1e {
  strings:
    $key_7d1e = { 2e 71 [2] 0a 7f [2] 21 53 [2] 0f 71 [2] 1b 6a [2] 14 70 [2] 0a 6d [2] 08 6c [2] 13 6a [2] 0f 6d [2] 13 42 }

  condition:
    any of them
}