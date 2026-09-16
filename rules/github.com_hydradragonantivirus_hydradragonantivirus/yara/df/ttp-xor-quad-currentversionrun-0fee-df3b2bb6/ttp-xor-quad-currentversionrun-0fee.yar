rule TTP_XOR_QUAD_CurrentVersionRun_0fee {
  strings:
    $key_0fee = { 5c 81 [2] 78 8f [2] 53 a3 [2] 7d 81 [2] 69 9a [2] 66 80 [2] 78 9d [2] 7a 9c [2] 61 9a [2] 7d 9d [2] 61 b2 }

  condition:
    any of them
}