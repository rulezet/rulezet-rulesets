rule TTP_XOR_QUAD_CurrentVersionRun_a9ee {
  strings:
    $key_a9ee = { fa 81 [2] de 8f [2] f5 a3 [2] db 81 [2] cf 9a [2] c0 80 [2] de 9d [2] dc 9c [2] c7 9a [2] db 9d [2] c7 b2 }

  condition:
    any of them
}