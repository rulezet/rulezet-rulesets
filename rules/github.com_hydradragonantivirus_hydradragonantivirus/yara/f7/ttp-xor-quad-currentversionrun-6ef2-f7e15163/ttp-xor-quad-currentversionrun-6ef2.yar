rule TTP_XOR_QUAD_CurrentVersionRun_6ef2 {
  strings:
    $key_6ef2 = { 3d 9d [2] 19 93 [2] 32 bf [2] 1c 9d [2] 08 86 [2] 07 9c [2] 19 81 [2] 1b 80 [2] 00 86 [2] 1c 81 [2] 00 ae }

  condition:
    any of them
}