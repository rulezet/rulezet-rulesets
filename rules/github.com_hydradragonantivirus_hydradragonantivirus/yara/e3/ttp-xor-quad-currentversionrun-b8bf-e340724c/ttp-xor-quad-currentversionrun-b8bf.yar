rule TTP_XOR_QUAD_CurrentVersionRun_b8bf {
  strings:
    $key_b8bf = { eb d0 [2] cf de [2] e4 f2 [2] ca d0 [2] de cb [2] d1 d1 [2] cf cc [2] cd cd [2] d6 cb [2] ca cc [2] d6 e3 }

  condition:
    any of them
}