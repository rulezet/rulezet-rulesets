rule TTP_XOR_QUAD_CurrentVersionRun_fff2 {
  strings:
    $key_fff2 = { ac 9d [2] 88 93 [2] a3 bf [2] 8d 9d [2] 99 86 [2] 96 9c [2] 88 81 [2] 8a 80 [2] 91 86 [2] 8d 81 [2] 91 ae }

  condition:
    any of them
}