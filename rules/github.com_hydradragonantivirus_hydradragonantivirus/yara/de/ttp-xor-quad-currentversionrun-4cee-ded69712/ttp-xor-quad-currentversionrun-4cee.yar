rule TTP_XOR_QUAD_CurrentVersionRun_4cee {
  strings:
    $key_4cee = { 1f 81 [2] 3b 8f [2] 10 a3 [2] 3e 81 [2] 2a 9a [2] 25 80 [2] 3b 9d [2] 39 9c [2] 22 9a [2] 3e 9d [2] 22 b2 }

  condition:
    any of them
}