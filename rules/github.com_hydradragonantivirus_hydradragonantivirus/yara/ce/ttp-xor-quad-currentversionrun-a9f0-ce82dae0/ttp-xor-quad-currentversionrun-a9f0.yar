rule TTP_XOR_QUAD_CurrentVersionRun_a9f0 {
  strings:
    $key_a9f0 = { fa 9f [2] de 91 [2] f5 bd [2] db 9f [2] cf 84 [2] c0 9e [2] de 83 [2] dc 82 [2] c7 84 [2] db 83 [2] c7 ac }

  condition:
    any of them
}