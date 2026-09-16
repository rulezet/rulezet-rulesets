rule TTP_XOR_QUAD_CurrentVersionRun_aeff {
  strings:
    $key_aeff = { fd 90 [2] d9 9e [2] f2 b2 [2] dc 90 [2] c8 8b [2] c7 91 [2] d9 8c [2] db 8d [2] c0 8b [2] dc 8c [2] c0 a3 }

  condition:
    any of them
}