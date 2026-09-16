rule TTP_XOR_MULT_DOSStub_945b {
  strings:
    $key_945b = { c0 33 [2] b4 2b [2] f3 29 [2] b4 38 [2] fa 34 [2] f6 3e [2] e1 35 [2] fa 7b [2] c7 }

  condition:
    any of them
}