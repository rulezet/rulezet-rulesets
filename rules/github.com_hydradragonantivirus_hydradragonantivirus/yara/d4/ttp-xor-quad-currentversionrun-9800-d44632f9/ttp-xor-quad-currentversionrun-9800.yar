rule TTP_XOR_QUAD_CurrentVersionRun_9800 {
  strings:
    $key_9800 = { cb 6f [2] ef 61 [2] c4 4d [2] ea 6f [2] fe 74 [2] f1 6e [2] ef 73 [2] ed 72 [2] f6 74 [2] ea 73 [2] f6 5c }

  condition:
    any of them
}