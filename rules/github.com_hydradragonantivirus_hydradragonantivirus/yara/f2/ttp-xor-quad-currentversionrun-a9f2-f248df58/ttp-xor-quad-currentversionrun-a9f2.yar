rule TTP_XOR_QUAD_CurrentVersionRun_a9f2 {
  strings:
    $key_a9f2 = { fa 9d [2] de 93 [2] f5 bf [2] db 9d [2] cf 86 [2] c0 9c [2] de 81 [2] dc 80 [2] c7 86 [2] db 81 [2] c7 ae }

  condition:
    any of them
}