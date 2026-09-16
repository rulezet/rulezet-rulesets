rule TTP_XOR_QUAD_CurrentVersionRun_2cee {
  strings:
    $key_2cee = { 7f 81 [2] 5b 8f [2] 70 a3 [2] 5e 81 [2] 4a 9a [2] 45 80 [2] 5b 9d [2] 59 9c [2] 42 9a [2] 5e 9d [2] 42 b2 }

  condition:
    any of them
}