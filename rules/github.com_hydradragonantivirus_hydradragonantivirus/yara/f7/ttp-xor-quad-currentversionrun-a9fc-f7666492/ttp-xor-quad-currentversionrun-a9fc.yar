rule TTP_XOR_QUAD_CurrentVersionRun_a9fc {
  strings:
    $key_a9fc = { fa 93 [2] de 9d [2] f5 b1 [2] db 93 [2] cf 88 [2] c0 92 [2] de 8f [2] dc 8e [2] c7 88 [2] db 8f [2] c7 a0 }

  condition:
    any of them
}