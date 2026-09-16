rule TTP_XOR_MULT_DOSStub_91bd {
  strings:
    $key_91bd = { c5 d5 [2] b1 cd [2] f6 cf [2] b1 de [2] ff d2 [2] f3 d8 [2] e4 d3 [2] ff 9d [2] c2 }

  condition:
    any of them
}