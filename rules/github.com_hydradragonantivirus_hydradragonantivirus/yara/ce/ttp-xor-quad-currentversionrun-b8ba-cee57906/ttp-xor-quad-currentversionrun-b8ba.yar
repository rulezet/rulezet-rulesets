rule TTP_XOR_QUAD_CurrentVersionRun_b8ba {
  strings:
    $key_b8ba = { eb d5 [2] cf db [2] e4 f7 [2] ca d5 [2] de ce [2] d1 d4 [2] cf c9 [2] cd c8 [2] d6 ce [2] ca c9 [2] d6 e6 }

  condition:
    any of them
}