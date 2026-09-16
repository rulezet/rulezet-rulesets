rule TTP_XOR_MULT_DOSStub_9121 {
  strings:
    $key_9121 = { c5 49 [2] b1 51 [2] f6 53 [2] b1 42 [2] ff 4e [2] f3 44 [2] e4 4f [2] ff 01 [2] c2 }

  condition:
    any of them
}