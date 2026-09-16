rule TTP_XOR_QUAD_CurrentVersionRun_57f2 {
  strings:
    $key_57f2 = { 04 9d [2] 20 93 [2] 0b bf [2] 25 9d [2] 31 86 [2] 3e 9c [2] 20 81 [2] 22 80 [2] 39 86 [2] 25 81 [2] 39 ae }

  condition:
    any of them
}