rule TTP_XOR_QUAD_CurrentVersionRun_90ba {
  strings:
    $key_90ba = { c3 d5 [2] e7 db [2] cc f7 [2] e2 d5 [2] f6 ce [2] f9 d4 [2] e7 c9 [2] e5 c8 [2] fe ce [2] e2 c9 [2] fe e6 }

  condition:
    any of them
}