rule TTP_XOR_QUAD_CurrentVersionRun_a9e3 {
  strings:
    $key_a9e3 = { fa 8c [2] de 82 [2] f5 ae [2] db 8c [2] cf 97 [2] c0 8d [2] de 90 [2] dc 91 [2] c7 97 [2] db 90 [2] c7 bf }

  condition:
    any of them
}