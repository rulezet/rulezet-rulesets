rule TTP_XOR_QUAD_CurrentVersionRun_987e {
  strings:
    $key_987e = { cb 11 [2] ef 1f [2] c4 33 [2] ea 11 [2] fe 0a [2] f1 10 [2] ef 0d [2] ed 0c [2] f6 0a [2] ea 0d [2] f6 22 }

  condition:
    any of them
}