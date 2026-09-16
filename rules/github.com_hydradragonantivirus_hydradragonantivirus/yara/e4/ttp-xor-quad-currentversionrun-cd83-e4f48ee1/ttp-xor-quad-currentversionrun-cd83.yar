rule TTP_XOR_QUAD_CurrentVersionRun_cd83 {
  strings:
    $key_cd83 = { 9e ec [2] ba e2 [2] 91 ce [2] bf ec [2] ab f7 [2] a4 ed [2] ba f0 [2] b8 f1 [2] a3 f7 [2] bf f0 [2] a3 df }

  condition:
    any of them
}