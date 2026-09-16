rule TTP_XOR_QUAD_CurrentVersionRun_98e1 {
  strings:
    $key_98e1 = { cb 8e [2] ef 80 [2] c4 ac [2] ea 8e [2] fe 95 [2] f1 8f [2] ef 92 [2] ed 93 [2] f6 95 [2] ea 92 [2] f6 bd }

  condition:
    any of them
}