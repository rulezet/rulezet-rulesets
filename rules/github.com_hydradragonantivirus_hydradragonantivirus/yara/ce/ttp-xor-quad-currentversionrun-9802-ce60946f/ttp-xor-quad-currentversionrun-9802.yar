rule TTP_XOR_QUAD_CurrentVersionRun_9802 {
  strings:
    $key_9802 = { cb 6d [2] ef 63 [2] c4 4f [2] ea 6d [2] fe 76 [2] f1 6c [2] ef 71 [2] ed 70 [2] f6 76 [2] ea 71 [2] f6 5e }

  condition:
    any of them
}