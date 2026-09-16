rule TTP_XOR_QUAD_CurrentVersionRun_a90d {
  strings:
    $key_a90d = { fa 62 [2] de 6c [2] f5 40 [2] db 62 [2] cf 79 [2] c0 63 [2] de 7e [2] dc 7f [2] c7 79 [2] db 7e [2] c7 51 }

  condition:
    any of them
}