rule TTP_XOR_QUAD_CurrentVersionRun_73f2 {
  strings:
    $key_73f2 = { 20 9d [2] 04 93 [2] 2f bf [2] 01 9d [2] 15 86 [2] 1a 9c [2] 04 81 [2] 06 80 [2] 1d 86 [2] 01 81 [2] 1d ae }

  condition:
    any of them
}