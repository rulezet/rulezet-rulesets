rule TTP_XOR_QUAD_CurrentVersionRun_ae11 {
  strings:
    $key_ae11 = { fd 7e [2] d9 70 [2] f2 5c [2] dc 7e [2] c8 65 [2] c7 7f [2] d9 62 [2] db 63 [2] c0 65 [2] dc 62 [2] c0 4d }

  condition:
    any of them
}