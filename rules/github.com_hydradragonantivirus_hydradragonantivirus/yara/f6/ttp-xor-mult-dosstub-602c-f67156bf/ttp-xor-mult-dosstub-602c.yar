rule TTP_XOR_MULT_DOSStub_602c {
  strings:
    $key_602c = { 34 44 [2] 40 5c [2] 07 5e [2] 40 4f [2] 0e 43 [2] 02 49 [2] 15 42 [2] 0e 0c [2] 33 }

  condition:
    any of them
}