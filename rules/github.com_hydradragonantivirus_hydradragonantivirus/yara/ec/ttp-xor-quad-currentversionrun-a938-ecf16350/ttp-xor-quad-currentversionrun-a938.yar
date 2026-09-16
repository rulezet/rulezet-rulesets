rule TTP_XOR_QUAD_CurrentVersionRun_a938 {
  strings:
    $key_a938 = { fa 57 [2] de 59 [2] f5 75 [2] db 57 [2] cf 4c [2] c0 56 [2] de 4b [2] dc 4a [2] c7 4c [2] db 4b [2] c7 64 }

  condition:
    any of them
}