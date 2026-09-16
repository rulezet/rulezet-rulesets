rule TTP_XOR_MULT_DOSStub_d92c {
  strings:
    $key_d92c = { 8d 44 [2] f9 5c [2] be 5e [2] f9 4f [2] b7 43 [2] bb 49 [2] ac 42 [2] b7 0c [2] 8a }

  condition:
    any of them
}