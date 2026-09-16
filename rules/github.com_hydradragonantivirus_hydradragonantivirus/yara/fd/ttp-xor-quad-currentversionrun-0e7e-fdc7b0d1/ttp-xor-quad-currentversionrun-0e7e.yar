rule TTP_XOR_QUAD_CurrentVersionRun_0e7e {
  strings:
    $key_0e7e = { 5d 11 [2] 79 1f [2] 52 33 [2] 7c 11 [2] 68 0a [2] 67 10 [2] 79 0d [2] 7b 0c [2] 60 0a [2] 7c 0d [2] 60 22 }

  condition:
    any of them
}