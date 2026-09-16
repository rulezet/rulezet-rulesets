rule TTP_XOR_QUAD_CurrentVersionRun_a926 {
  strings:
    $key_a926 = { fa 49 [2] de 47 [2] f5 6b [2] db 49 [2] cf 52 [2] c0 48 [2] de 55 [2] dc 54 [2] c7 52 [2] db 55 [2] c7 7a }

  condition:
    any of them
}