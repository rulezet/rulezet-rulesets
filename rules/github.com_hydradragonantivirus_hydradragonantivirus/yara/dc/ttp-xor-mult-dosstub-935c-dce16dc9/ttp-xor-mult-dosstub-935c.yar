rule TTP_XOR_MULT_DOSStub_935c {
  strings:
    $key_935c = { c7 34 [2] b3 2c [2] f4 2e [2] b3 3f [2] fd 33 [2] f1 39 [2] e6 32 [2] fd 7c [2] c0 }

  condition:
    any of them
}