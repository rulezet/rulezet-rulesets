rule TTP_XOR_MULT_DOSStub_a41c {
  strings:
    $key_a41c = { f0 74 [2] 84 6c [2] c3 6e [2] 84 7f [2] ca 73 [2] c6 79 [2] d1 72 [2] ca 3c [2] f7 }

  condition:
    any of them
}