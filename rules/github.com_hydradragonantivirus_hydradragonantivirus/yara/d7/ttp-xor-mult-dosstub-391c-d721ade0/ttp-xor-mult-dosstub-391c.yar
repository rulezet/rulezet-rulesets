rule TTP_XOR_MULT_DOSStub_391c {
  strings:
    $key_391c = { 6d 74 [2] 19 6c [2] 5e 6e [2] 19 7f [2] 57 73 [2] 5b 79 [2] 4c 72 [2] 57 3c [2] 6a }

  condition:
    any of them
}