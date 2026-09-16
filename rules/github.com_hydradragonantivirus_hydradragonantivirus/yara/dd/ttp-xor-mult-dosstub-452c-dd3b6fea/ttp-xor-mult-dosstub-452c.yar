rule TTP_XOR_MULT_DOSStub_452c {
  strings:
    $key_452c = { 11 44 [2] 65 5c [2] 22 5e [2] 65 4f [2] 2b 43 [2] 27 49 [2] 30 42 [2] 2b 0c [2] 16 }

  condition:
    any of them
}