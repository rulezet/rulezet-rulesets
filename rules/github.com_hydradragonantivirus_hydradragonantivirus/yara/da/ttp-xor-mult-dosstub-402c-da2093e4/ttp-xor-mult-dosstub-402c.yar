rule TTP_XOR_MULT_DOSStub_402c {
  strings:
    $key_402c = { 14 44 [2] 60 5c [2] 27 5e [2] 60 4f [2] 2e 43 [2] 22 49 [2] 35 42 [2] 2e 0c [2] 13 }

  condition:
    any of them
}