rule TTP_XOR_QUAD_CurrentVersionRun_6fee {
  strings:
    $key_6fee = { 3c 81 [2] 18 8f [2] 33 a3 [2] 1d 81 [2] 09 9a [2] 06 80 [2] 18 9d [2] 1a 9c [2] 01 9a [2] 1d 9d [2] 01 b2 }

  condition:
    any of them
}