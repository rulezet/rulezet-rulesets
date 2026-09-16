rule TTP_XOR_QUAD_CurrentVersionRun_46ee {
  strings:
    $key_46ee = { 15 81 [2] 31 8f [2] 1a a3 [2] 34 81 [2] 20 9a [2] 2f 80 [2] 31 9d [2] 33 9c [2] 28 9a [2] 34 9d [2] 28 b2 }

  condition:
    any of them
}