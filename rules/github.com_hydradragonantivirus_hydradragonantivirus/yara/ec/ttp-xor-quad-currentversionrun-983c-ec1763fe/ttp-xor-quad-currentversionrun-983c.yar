rule TTP_XOR_QUAD_CurrentVersionRun_983c {
  strings:
    $key_983c = { cb 53 [2] ef 5d [2] c4 71 [2] ea 53 [2] fe 48 [2] f1 52 [2] ef 4f [2] ed 4e [2] f6 48 [2] ea 4f [2] f6 60 }

  condition:
    any of them
}