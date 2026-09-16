rule TTP_XOR_QUAD_CurrentVersionRun_a8af {
  strings:
    $key_a8af = { fb c0 [2] df ce [2] f4 e2 [2] da c0 [2] ce db [2] c1 c1 [2] df dc [2] dd dd [2] c6 db [2] da dc [2] c6 f3 }

  condition:
    any of them
}