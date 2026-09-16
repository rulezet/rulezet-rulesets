rule TTP_XOR_MULT_DOSStub_933e {
  strings:
    $key_933e = { c7 56 [2] b3 4e [2] f4 4c [2] b3 5d [2] fd 51 [2] f1 5b [2] e6 50 [2] fd 1e [2] c0 }

  condition:
    any of them
}