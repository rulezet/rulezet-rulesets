rule TTP_XOR_MULT_DOSStub_a42c {
  strings:
    $key_a42c = { f0 44 [2] 84 5c [2] c3 5e [2] 84 4f [2] ca 43 [2] c6 49 [2] d1 42 [2] ca 0c [2] f7 }

  condition:
    any of them
}