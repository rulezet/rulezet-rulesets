rule TTP_XOR_MULT_DOSStub_d41c {
  strings:
    $key_d41c = { 80 74 [2] f4 6c [2] b3 6e [2] f4 7f [2] ba 73 [2] b6 79 [2] a1 72 [2] ba 3c [2] 87 }

  condition:
    any of them
}