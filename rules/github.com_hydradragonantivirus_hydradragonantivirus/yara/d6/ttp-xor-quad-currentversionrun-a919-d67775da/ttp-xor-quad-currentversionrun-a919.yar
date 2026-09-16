rule TTP_XOR_QUAD_CurrentVersionRun_a919 {
  strings:
    $key_a919 = { fa 76 [2] de 78 [2] f5 54 [2] db 76 [2] cf 6d [2] c0 77 [2] de 6a [2] dc 6b [2] c7 6d [2] db 6a [2] c7 45 }

  condition:
    any of them
}