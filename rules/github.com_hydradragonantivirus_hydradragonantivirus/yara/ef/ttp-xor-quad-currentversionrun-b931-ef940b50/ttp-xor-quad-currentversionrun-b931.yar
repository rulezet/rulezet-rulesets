rule TTP_XOR_QUAD_CurrentVersionRun_b931 {
  strings:
    $key_b931 = { ea 5e [2] ce 50 [2] e5 7c [2] cb 5e [2] df 45 [2] d0 5f [2] ce 42 [2] cc 43 [2] d7 45 [2] cb 42 [2] d7 6d }

  condition:
    any of them
}