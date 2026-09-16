rule TTP_XOR_QUAD_CurrentVersionRun_affe {
  strings:
    $key_affe = { fc 91 [2] d8 9f [2] f3 b3 [2] dd 91 [2] c9 8a [2] c6 90 [2] d8 8d [2] da 8c [2] c1 8a [2] dd 8d [2] c1 a2 }

  condition:
    any of them
}