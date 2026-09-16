rule TTP_XOR_QUAD_CurrentVersionRun_a92d {
  strings:
    $key_a92d = { fa 42 [2] de 4c [2] f5 60 [2] db 42 [2] cf 59 [2] c0 43 [2] de 5e [2] dc 5f [2] c7 59 [2] db 5e [2] c7 71 }

  condition:
    any of them
}