rule TTP_XOR_MULT_DOSStub_912e {
  strings:
    $key_912e = { c5 46 [2] b1 5e [2] f6 5c [2] b1 4d [2] ff 41 [2] f3 4b [2] e4 40 [2] ff 0e [2] c2 }

  condition:
    any of them
}