rule TTP_XOR_QUAD_CurrentVersionRun_6cee {
  strings:
    $key_6cee = { 3f 81 [2] 1b 8f [2] 30 a3 [2] 1e 81 [2] 0a 9a [2] 05 80 [2] 1b 9d [2] 19 9c [2] 02 9a [2] 1e 9d [2] 02 b2 }

  condition:
    any of them
}