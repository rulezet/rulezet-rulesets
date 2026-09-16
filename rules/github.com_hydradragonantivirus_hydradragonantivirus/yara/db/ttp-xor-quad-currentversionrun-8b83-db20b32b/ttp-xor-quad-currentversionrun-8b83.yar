rule TTP_XOR_QUAD_CurrentVersionRun_8b83 {
  strings:
    $key_8b83 = { d8 ec [2] fc e2 [2] d7 ce [2] f9 ec [2] ed f7 [2] e2 ed [2] fc f0 [2] fe f1 [2] e5 f7 [2] f9 f0 [2] e5 df }

  condition:
    any of them
}