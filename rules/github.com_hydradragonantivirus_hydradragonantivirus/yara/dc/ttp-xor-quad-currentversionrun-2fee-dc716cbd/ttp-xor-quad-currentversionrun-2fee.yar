rule TTP_XOR_QUAD_CurrentVersionRun_2fee {
  strings:
    $key_2fee = { 7c 81 [2] 58 8f [2] 73 a3 [2] 5d 81 [2] 49 9a [2] 46 80 [2] 58 9d [2] 5a 9c [2] 41 9a [2] 5d 9d [2] 41 b2 }

  condition:
    any of them
}