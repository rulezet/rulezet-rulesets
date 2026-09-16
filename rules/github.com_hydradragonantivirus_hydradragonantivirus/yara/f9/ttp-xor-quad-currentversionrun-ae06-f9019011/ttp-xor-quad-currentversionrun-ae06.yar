rule TTP_XOR_QUAD_CurrentVersionRun_ae06 {
  strings:
    $key_ae06 = { fd 69 [2] d9 67 [2] f2 4b [2] dc 69 [2] c8 72 [2] c7 68 [2] d9 75 [2] db 74 [2] c0 72 [2] dc 75 [2] c0 5a }

  condition:
    any of them
}