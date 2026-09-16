rule TTP_XOR_QUAD_CurrentVersionRun_627e {
  strings:
    $key_627e = { 31 11 [2] 15 1f [2] 3e 33 [2] 10 11 [2] 04 0a [2] 0b 10 [2] 15 0d [2] 17 0c [2] 0c 0a [2] 10 0d [2] 0c 22 }

  condition:
    any of them
}