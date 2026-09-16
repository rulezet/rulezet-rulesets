rule TTP_XOR_MULT_DOSStub_943d {
  strings:
    $key_943d = { c0 55 [2] b4 4d [2] f3 4f [2] b4 5e [2] fa 52 [2] f6 58 [2] e1 53 [2] fa 1d [2] c7 }

  condition:
    any of them
}