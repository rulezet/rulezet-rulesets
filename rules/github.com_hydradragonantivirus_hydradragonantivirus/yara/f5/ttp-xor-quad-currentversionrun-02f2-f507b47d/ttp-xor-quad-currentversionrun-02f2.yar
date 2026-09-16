rule TTP_XOR_QUAD_CurrentVersionRun_02f2 {
  strings:
    $key_02f2 = { 51 9d [2] 75 93 [2] 5e bf [2] 70 9d [2] 64 86 [2] 6b 9c [2] 75 81 [2] 77 80 [2] 6c 86 [2] 70 81 [2] 6c ae }

  condition:
    any of them
}