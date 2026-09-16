rule TTP_XOR_QUAD_CurrentVersionRun_a950 {
  strings:
    $key_a950 = { fa 3f [2] de 31 [2] f5 1d [2] db 3f [2] cf 24 [2] c0 3e [2] de 23 [2] dc 22 [2] c7 24 [2] db 23 [2] c7 0c }

  condition:
    any of them
}