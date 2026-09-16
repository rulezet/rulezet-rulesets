rule TTP_XOR_MULT_DOSStub_831d {
  strings:
    $key_831d = { d7 75 [2] a3 6d [2] e4 6f [2] a3 7e [2] ed 72 [2] e1 78 [2] f6 73 [2] ed 3d [2] d0 }

  condition:
    any of them
}