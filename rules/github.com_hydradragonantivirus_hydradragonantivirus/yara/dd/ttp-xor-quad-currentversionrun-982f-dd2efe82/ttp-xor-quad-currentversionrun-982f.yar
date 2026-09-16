rule TTP_XOR_QUAD_CurrentVersionRun_982f {
  strings:
    $key_982f = { cb 40 [2] ef 4e [2] c4 62 [2] ea 40 [2] fe 5b [2] f1 41 [2] ef 5c [2] ed 5d [2] f6 5b [2] ea 5c [2] f6 73 }

  condition:
    any of them
}