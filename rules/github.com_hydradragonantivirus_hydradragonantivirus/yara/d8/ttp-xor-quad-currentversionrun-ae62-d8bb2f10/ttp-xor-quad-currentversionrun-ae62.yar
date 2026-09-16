rule TTP_XOR_QUAD_CurrentVersionRun_ae62 {
  strings:
    $key_ae62 = { fd 0d [2] d9 03 [2] f2 2f [2] dc 0d [2] c8 16 [2] c7 0c [2] d9 11 [2] db 10 [2] c0 16 [2] dc 11 [2] c0 3e }

  condition:
    any of them
}