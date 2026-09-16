rule TTP_XOR_MULT_DOSStub_371c {
  strings:
    $key_371c = { 63 74 [2] 17 6c [2] 50 6e [2] 17 7f [2] 59 73 [2] 55 79 [2] 42 72 [2] 59 3c [2] 64 }

  condition:
    any of them
}