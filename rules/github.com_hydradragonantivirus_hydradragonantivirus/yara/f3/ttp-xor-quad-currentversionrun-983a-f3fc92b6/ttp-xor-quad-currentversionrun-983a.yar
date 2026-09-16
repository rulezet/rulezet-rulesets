rule TTP_XOR_QUAD_CurrentVersionRun_983a {
  strings:
    $key_983a = { cb 55 [2] ef 5b [2] c4 77 [2] ea 55 [2] fe 4e [2] f1 54 [2] ef 49 [2] ed 48 [2] f6 4e [2] ea 49 [2] f6 66 }

  condition:
    any of them
}