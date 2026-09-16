rule TTP_XOR_QUAD_CurrentVersionRun_01ee {
  strings:
    $key_01ee = { 52 81 [2] 76 8f [2] 5d a3 [2] 73 81 [2] 67 9a [2] 68 80 [2] 76 9d [2] 74 9c [2] 6f 9a [2] 73 9d [2] 6f b2 }

  condition:
    any of them
}