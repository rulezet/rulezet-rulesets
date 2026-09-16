rule TTP_XOR_QUAD_CurrentVersionRun_9871 {
  strings:
    $key_9871 = { cb 1e [2] ef 10 [2] c4 3c [2] ea 1e [2] fe 05 [2] f1 1f [2] ef 02 [2] ed 03 [2] f6 05 [2] ea 02 [2] f6 2d }

  condition:
    any of them
}