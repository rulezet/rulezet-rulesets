rule TTP_XOR_QUAD_CurrentVersionRun_978c {
  strings:
    $key_978c = { c4 e3 [2] e0 ed [2] cb c1 [2] e5 e3 [2] f1 f8 [2] fe e2 [2] e0 ff [2] e2 fe [2] f9 f8 [2] e5 ff [2] f9 d0 }

  condition:
    any of them
}