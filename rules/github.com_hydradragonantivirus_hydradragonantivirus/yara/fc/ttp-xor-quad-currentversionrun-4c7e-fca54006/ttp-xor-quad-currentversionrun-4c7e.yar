rule TTP_XOR_QUAD_CurrentVersionRun_4c7e {
  strings:
    $key_4c7e = { 1f 11 [2] 3b 1f [2] 10 33 [2] 3e 11 [2] 2a 0a [2] 25 10 [2] 3b 0d [2] 39 0c [2] 22 0a [2] 3e 0d [2] 22 22 }

  condition:
    any of them
}