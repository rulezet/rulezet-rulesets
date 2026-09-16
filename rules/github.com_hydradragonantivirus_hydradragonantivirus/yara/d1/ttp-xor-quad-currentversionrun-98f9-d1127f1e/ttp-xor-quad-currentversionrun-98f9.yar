rule TTP_XOR_QUAD_CurrentVersionRun_98f9 {
  strings:
    $key_98f9 = { cb 96 [2] ef 98 [2] c4 b4 [2] ea 96 [2] fe 8d [2] f1 97 [2] ef 8a [2] ed 8b [2] f6 8d [2] ea 8a [2] f6 a5 }

  condition:
    any of them
}