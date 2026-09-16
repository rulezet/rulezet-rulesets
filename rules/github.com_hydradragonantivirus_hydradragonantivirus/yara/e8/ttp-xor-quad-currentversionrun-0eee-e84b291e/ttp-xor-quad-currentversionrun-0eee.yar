rule TTP_XOR_QUAD_CurrentVersionRun_0eee {
  strings:
    $key_0eee = { 5d 81 [2] 79 8f [2] 52 a3 [2] 7c 81 [2] 68 9a [2] 67 80 [2] 79 9d [2] 7b 9c [2] 60 9a [2] 7c 9d [2] 60 b2 }

  condition:
    any of them
}