rule TTP_XOR_MULT_DOSStub_002c {
  strings:
    $key_002c = { 54 44 [2] 20 5c [2] 67 5e [2] 20 4f [2] 6e 43 [2] 62 49 [2] 75 42 [2] 6e 0c [2] 53 }

  condition:
    any of them
}