rule TTP_XOR_QUAD_CurrentVersionRun_af1f {
  strings:
    $key_af1f = { fc 70 [2] d8 7e [2] f3 52 [2] dd 70 [2] c9 6b [2] c6 71 [2] d8 6c [2] da 6d [2] c1 6b [2] dd 6c [2] c1 43 }

  condition:
    any of them
}