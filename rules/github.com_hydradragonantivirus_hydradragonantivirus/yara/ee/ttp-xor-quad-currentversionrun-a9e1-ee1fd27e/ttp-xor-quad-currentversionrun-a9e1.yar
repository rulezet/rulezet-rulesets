rule TTP_XOR_QUAD_CurrentVersionRun_a9e1 {
  strings:
    $key_a9e1 = { fa 8e [2] de 80 [2] f5 ac [2] db 8e [2] cf 95 [2] c0 8f [2] de 92 [2] dc 93 [2] c7 95 [2] db 92 [2] c7 bd }

  condition:
    any of them
}