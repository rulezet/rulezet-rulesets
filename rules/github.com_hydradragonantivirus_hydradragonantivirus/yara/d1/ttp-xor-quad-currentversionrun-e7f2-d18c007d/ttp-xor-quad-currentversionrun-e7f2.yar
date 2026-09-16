rule TTP_XOR_QUAD_CurrentVersionRun_e7f2 {
  strings:
    $key_e7f2 = { b4 9d [2] 90 93 [2] bb bf [2] 95 9d [2] 81 86 [2] 8e 9c [2] 90 81 [2] 92 80 [2] 89 86 [2] 95 81 [2] 89 ae }

  condition:
    any of them
}