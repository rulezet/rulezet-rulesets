rule TTP_XOR_QUAD_CurrentVersionRun_24f2 {
  strings:
    $key_24f2 = { 77 9d [2] 53 93 [2] 78 bf [2] 56 9d [2] 42 86 [2] 4d 9c [2] 53 81 [2] 51 80 [2] 4a 86 [2] 56 81 [2] 4a ae }

  condition:
    any of them
}