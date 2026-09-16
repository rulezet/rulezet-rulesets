rule TTP_XOR_QUAD_CurrentVersionRun_e683 {
  strings:
    $key_e683 = { b5 ec [2] 91 e2 [2] ba ce [2] 94 ec [2] 80 f7 [2] 8f ed [2] 91 f0 [2] 93 f1 [2] 88 f7 [2] 94 f0 [2] 88 df }

  condition:
    any of them
}