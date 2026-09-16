rule TTP_XOR_QUAD_CurrentVersionRun_34f2 {
  strings:
    $key_34f2 = { 67 9d [2] 43 93 [2] 68 bf [2] 46 9d [2] 52 86 [2] 5d 9c [2] 43 81 [2] 41 80 [2] 5a 86 [2] 46 81 [2] 5a ae }

  condition:
    any of them
}