rule TTP_XOR_QUAD_CurrentVersionRun_aee0 {
  strings:
    $key_aee0 = { fd 8f [2] d9 81 [2] f2 ad [2] dc 8f [2] c8 94 [2] c7 8e [2] d9 93 [2] db 92 [2] c0 94 [2] dc 93 [2] c0 bc }

  condition:
    any of them
}