rule TTP_XOR_QUAD_CurrentVersionRun_a908 {
  strings:
    $key_a908 = { fa 67 [2] de 69 [2] f5 45 [2] db 67 [2] cf 7c [2] c0 66 [2] de 7b [2] dc 7a [2] c7 7c [2] db 7b [2] c7 54 }

  condition:
    any of them
}