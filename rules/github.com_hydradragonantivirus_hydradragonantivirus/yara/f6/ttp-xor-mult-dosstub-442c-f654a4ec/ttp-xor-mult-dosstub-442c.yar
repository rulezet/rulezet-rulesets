rule TTP_XOR_MULT_DOSStub_442c {
  strings:
    $key_442c = { 10 44 [2] 64 5c [2] 23 5e [2] 64 4f [2] 2a 43 [2] 26 49 [2] 31 42 [2] 2a 0c [2] 17 }

  condition:
    any of them
}