rule TTP_XOR_QUAD_CurrentVersionRun_d483 {
  strings:
    $key_d483 = { 87 ec [2] a3 e2 [2] 88 ce [2] a6 ec [2] b2 f7 [2] bd ed [2] a3 f0 [2] a1 f1 [2] ba f7 [2] a6 f0 [2] ba df }

  condition:
    any of them
}