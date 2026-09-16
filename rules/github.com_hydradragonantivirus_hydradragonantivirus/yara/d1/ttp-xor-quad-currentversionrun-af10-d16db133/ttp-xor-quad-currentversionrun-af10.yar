rule TTP_XOR_QUAD_CurrentVersionRun_af10 {
  strings:
    $key_af10 = { fc 7f [2] d8 71 [2] f3 5d [2] dd 7f [2] c9 64 [2] c6 7e [2] d8 63 [2] da 62 [2] c1 64 [2] dd 63 [2] c1 4c }

  condition:
    any of them
}