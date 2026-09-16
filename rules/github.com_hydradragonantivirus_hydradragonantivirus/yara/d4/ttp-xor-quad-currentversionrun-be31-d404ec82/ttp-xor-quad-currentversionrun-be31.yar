rule TTP_XOR_QUAD_CurrentVersionRun_be31 {
  strings:
    $key_be31 = { ed 5e [2] c9 50 [2] e2 7c [2] cc 5e [2] d8 45 [2] d7 5f [2] c9 42 [2] cb 43 [2] d0 45 [2] cc 42 [2] d0 6d }

  condition:
    any of them
}