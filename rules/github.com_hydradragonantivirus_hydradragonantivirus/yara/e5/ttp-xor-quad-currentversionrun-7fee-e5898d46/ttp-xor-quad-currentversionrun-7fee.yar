rule TTP_XOR_QUAD_CurrentVersionRun_7fee {
  strings:
    $key_7fee = { 2c 81 [2] 08 8f [2] 23 a3 [2] 0d 81 [2] 19 9a [2] 16 80 [2] 08 9d [2] 0a 9c [2] 11 9a [2] 0d 9d [2] 11 b2 }

  condition:
    any of them
}