rule TTP_XOR_QUAD_CurrentVersionRun_88c9 {
  strings:
    $key_88c9 = { db a6 [2] ff a8 [2] d4 84 [2] fa a6 [2] ee bd [2] e1 a7 [2] ff ba [2] fd bb [2] e6 bd [2] fa ba [2] e6 95 }

  condition:
    any of them
}