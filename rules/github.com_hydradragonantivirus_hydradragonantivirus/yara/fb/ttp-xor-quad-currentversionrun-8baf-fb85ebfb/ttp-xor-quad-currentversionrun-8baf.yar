rule TTP_XOR_QUAD_CurrentVersionRun_8baf {
  strings:
    $key_8baf = { d8 c0 [2] fc ce [2] d7 e2 [2] f9 c0 [2] ed db [2] e2 c1 [2] fc dc [2] fe dd [2] e5 db [2] f9 dc [2] e5 f3 }

  condition:
    any of them
}