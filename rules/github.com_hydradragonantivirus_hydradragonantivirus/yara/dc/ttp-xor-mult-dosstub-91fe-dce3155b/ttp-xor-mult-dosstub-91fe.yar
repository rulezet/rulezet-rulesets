rule TTP_XOR_MULT_DOSStub_91fe {
  strings:
    $key_91fe = { c5 96 [2] b1 8e [2] f6 8c [2] b1 9d [2] ff 91 [2] f3 9b [2] e4 90 [2] ff de [2] c2 }

  condition:
    any of them
}