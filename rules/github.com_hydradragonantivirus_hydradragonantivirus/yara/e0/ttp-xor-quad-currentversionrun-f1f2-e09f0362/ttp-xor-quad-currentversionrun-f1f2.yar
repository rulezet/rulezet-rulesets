rule TTP_XOR_QUAD_CurrentVersionRun_f1f2 {
  strings:
    $key_f1f2 = { a2 9d [2] 86 93 [2] ad bf [2] 83 9d [2] 97 86 [2] 98 9c [2] 86 81 [2] 84 80 [2] 9f 86 [2] 83 81 [2] 9f ae }

  condition:
    any of them
}