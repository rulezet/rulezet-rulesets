rule TTP_XOR_MULT_DOSStub_344c {
  strings:
    $key_344c = { 60 24 [2] 14 3c [2] 53 3e [2] 14 2f [2] 5a 23 [2] 56 29 [2] 41 22 [2] 5a 6c [2] 67 }

  condition:
    any of them
}