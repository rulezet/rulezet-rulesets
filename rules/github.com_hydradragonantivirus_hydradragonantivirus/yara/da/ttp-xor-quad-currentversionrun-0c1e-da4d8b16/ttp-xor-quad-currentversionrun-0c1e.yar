rule TTP_XOR_QUAD_CurrentVersionRun_0c1e {
  strings:
    $key_0c1e = { 5f 71 [2] 7b 7f [2] 50 53 [2] 7e 71 [2] 6a 6a [2] 65 70 [2] 7b 6d [2] 79 6c [2] 62 6a [2] 7e 6d [2] 62 42 }

  condition:
    any of them
}