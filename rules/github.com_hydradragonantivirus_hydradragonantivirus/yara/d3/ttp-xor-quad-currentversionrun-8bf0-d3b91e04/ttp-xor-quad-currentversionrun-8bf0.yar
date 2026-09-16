rule TTP_XOR_QUAD_CurrentVersionRun_8bf0 {
  strings:
    $key_8bf0 = { d8 9f [2] fc 91 [2] d7 bd [2] f9 9f [2] ed 84 [2] e2 9e [2] fc 83 [2] fe 82 [2] e5 84 [2] f9 83 [2] e5 ac }

  condition:
    any of them
}