rule TTP_XOR_MULT_DOSStub_d7fe {
  strings:
    $key_d7fe = { 83 96 [2] f7 8e [2] b0 8c [2] f7 9d [2] b9 91 [2] b5 9b [2] a2 90 [2] b9 de [2] 84 }

  condition:
    any of them
}