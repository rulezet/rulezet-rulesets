rule TTP_XOR_QUAD_CurrentVersionRun_8683 {
  strings:
    $key_8683 = { d5 ec [2] f1 e2 [2] da ce [2] f4 ec [2] e0 f7 [2] ef ed [2] f1 f0 [2] f3 f1 [2] e8 f7 [2] f4 f0 [2] e8 df }

  condition:
    any of them
}