rule TTP_XOR_QUAD_CurrentVersionRun_9ae1 {
  strings:
    $key_9ae1 = { c9 8e [2] ed 80 [2] c6 ac [2] e8 8e [2] fc 95 [2] f3 8f [2] ed 92 [2] ef 93 [2] f4 95 [2] e8 92 [2] f4 bd }

  condition:
    any of them
}