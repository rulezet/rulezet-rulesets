rule TTP_XOR_QUAD_CurrentVersionRun_8d31 {
  strings:
    $key_8d31 = { de 5e [2] fa 50 [2] d1 7c [2] ff 5e [2] eb 45 [2] e4 5f [2] fa 42 [2] f8 43 [2] e3 45 [2] ff 42 [2] e3 6d }

  condition:
    any of them
}