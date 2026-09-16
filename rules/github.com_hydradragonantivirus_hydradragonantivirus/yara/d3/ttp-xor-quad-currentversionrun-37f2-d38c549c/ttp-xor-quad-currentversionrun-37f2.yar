rule TTP_XOR_QUAD_CurrentVersionRun_37f2 {
  strings:
    $key_37f2 = { 64 9d [2] 40 93 [2] 6b bf [2] 45 9d [2] 51 86 [2] 5e 9c [2] 40 81 [2] 42 80 [2] 59 86 [2] 45 81 [2] 59 ae }

  condition:
    any of them
}