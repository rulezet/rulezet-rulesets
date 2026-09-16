rule TTP_XOR_QUAD_CurrentVersionRun_19f2 {
  strings:
    $key_19f2 = { 4a 9d [2] 6e 93 [2] 45 bf [2] 6b 9d [2] 7f 86 [2] 70 9c [2] 6e 81 [2] 6c 80 [2] 77 86 [2] 6b 81 [2] 77 ae }

  condition:
    any of them
}