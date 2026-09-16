rule TTP_XOR_MULT_DOSStub_942e {
  strings:
    $key_942e = { c0 46 [2] b4 5e [2] f3 5c [2] b4 4d [2] fa 41 [2] f6 4b [2] e1 40 [2] fa 0e [2] c7 }

  condition:
    any of them
}