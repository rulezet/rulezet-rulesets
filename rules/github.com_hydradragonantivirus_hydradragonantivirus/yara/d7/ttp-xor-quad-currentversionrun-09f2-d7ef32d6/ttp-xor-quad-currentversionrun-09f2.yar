rule TTP_XOR_QUAD_CurrentVersionRun_09f2 {
  strings:
    $key_09f2 = { 5a 9d [2] 7e 93 [2] 55 bf [2] 7b 9d [2] 6f 86 [2] 60 9c [2] 7e 81 [2] 7c 80 [2] 67 86 [2] 7b 81 [2] 67 ae }

  condition:
    any of them
}