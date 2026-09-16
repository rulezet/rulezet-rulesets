rule TTP_XOR_QUAD_CurrentVersionRun_bc98 {
  strings:
    $key_bc98 = { ef f7 [2] cb f9 [2] e0 d5 [2] ce f7 [2] da ec [2] d5 f6 [2] cb eb [2] c9 ea [2] d2 ec [2] ce eb [2] d2 c4 }

  condition:
    any of them
}