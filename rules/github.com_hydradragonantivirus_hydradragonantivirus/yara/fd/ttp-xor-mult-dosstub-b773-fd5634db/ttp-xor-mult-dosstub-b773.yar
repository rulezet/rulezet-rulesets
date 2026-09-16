rule TTP_XOR_MULT_DOSStub_b773 {
  strings:
    $key_b773 = { e3 1b [2] 97 03 [2] d0 01 [2] 97 10 [2] d9 1c [2] d5 16 [2] c2 1d [2] d9 53 [2] e4 }

  condition:
    any of them
}