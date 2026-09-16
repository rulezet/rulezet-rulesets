rule TTP_XOR_MULT_DOSStub_a01c {
  strings:
    $key_a01c = { f4 74 [2] 80 6c [2] c7 6e [2] 80 7f [2] ce 73 [2] c2 79 [2] d5 72 [2] ce 3c [2] f3 }

  condition:
    any of them
}