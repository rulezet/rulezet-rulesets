rule TTP_XOR_QUAD_CurrentVersionRun_44f2 {
  strings:
    $key_44f2 = { 17 9d [2] 33 93 [2] 18 bf [2] 36 9d [2] 22 86 [2] 2d 9c [2] 33 81 [2] 31 80 [2] 2a 86 [2] 36 81 [2] 2a ae }

  condition:
    any of them
}