rule TTP_XOR_MULT_DOSStub_324c {
  strings:
    $key_324c = { 66 24 [2] 12 3c [2] 55 3e [2] 12 2f [2] 5c 23 [2] 50 29 [2] 47 22 [2] 5c 6c [2] 61 }

  condition:
    any of them
}