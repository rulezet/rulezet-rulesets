rule TTP_XOR_QUAD_CurrentVersionRun_b88a {
  strings:
    $key_b88a = { eb e5 [2] cf eb [2] e4 c7 [2] ca e5 [2] de fe [2] d1 e4 [2] cf f9 [2] cd f8 [2] d6 fe [2] ca f9 [2] d6 d6 }

  condition:
    any of them
}