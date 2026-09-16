rule TTP_XOR_QUAD_CurrentVersionRun_41ee {
  strings:
    $key_41ee = { 12 81 [2] 36 8f [2] 1d a3 [2] 33 81 [2] 27 9a [2] 28 80 [2] 36 9d [2] 34 9c [2] 2f 9a [2] 33 9d [2] 2f b2 }

  condition:
    any of them
}