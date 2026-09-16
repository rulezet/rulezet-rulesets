rule TTP_XOR_QUAD_CurrentVersionRun_56ee {
  strings:
    $key_56ee = { 05 81 [2] 21 8f [2] 0a a3 [2] 24 81 [2] 30 9a [2] 3f 80 [2] 21 9d [2] 23 9c [2] 38 9a [2] 24 9d [2] 38 b2 }

  condition:
    any of them
}