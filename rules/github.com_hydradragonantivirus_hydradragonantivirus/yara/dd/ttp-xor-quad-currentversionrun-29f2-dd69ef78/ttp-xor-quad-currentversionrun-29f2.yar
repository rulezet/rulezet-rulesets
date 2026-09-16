rule TTP_XOR_QUAD_CurrentVersionRun_29f2 {
  strings:
    $key_29f2 = { 7a 9d [2] 5e 93 [2] 75 bf [2] 5b 9d [2] 4f 86 [2] 40 9c [2] 5e 81 [2] 5c 80 [2] 47 86 [2] 5b 81 [2] 47 ae }

  condition:
    any of them
}