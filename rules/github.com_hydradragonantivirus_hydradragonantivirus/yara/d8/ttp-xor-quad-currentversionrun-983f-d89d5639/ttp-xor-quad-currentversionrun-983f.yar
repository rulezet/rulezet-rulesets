rule TTP_XOR_QUAD_CurrentVersionRun_983f {
  strings:
    $key_983f = { cb 50 [2] ef 5e [2] c4 72 [2] ea 50 [2] fe 4b [2] f1 51 [2] ef 4c [2] ed 4d [2] f6 4b [2] ea 4c [2] f6 63 }

  condition:
    any of them
}