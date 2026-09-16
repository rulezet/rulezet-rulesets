rule TTP_XOR_MULT_DOSStub_d0fe {
  strings:
    $key_d0fe = { 84 96 [2] f0 8e [2] b7 8c [2] f0 9d [2] be 91 [2] b2 9b [2] a5 90 [2] be de [2] 83 }

  condition:
    any of them
}