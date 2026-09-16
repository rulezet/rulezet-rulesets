rule TTP_XOR_QUAD_CurrentVersionRun_3cee {
  strings:
    $key_3cee = { 6f 81 [2] 4b 8f [2] 60 a3 [2] 4e 81 [2] 5a 9a [2] 55 80 [2] 4b 9d [2] 49 9c [2] 52 9a [2] 4e 9d [2] 52 b2 }

  condition:
    any of them
}