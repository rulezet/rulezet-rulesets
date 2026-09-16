rule TTP_XOR_QUAD_CurrentVersionRun_a920 {
  strings:
    $key_a920 = { fa 4f [2] de 41 [2] f5 6d [2] db 4f [2] cf 54 [2] c0 4e [2] de 53 [2] dc 52 [2] c7 54 [2] db 53 [2] c7 7c }

  condition:
    any of them
}