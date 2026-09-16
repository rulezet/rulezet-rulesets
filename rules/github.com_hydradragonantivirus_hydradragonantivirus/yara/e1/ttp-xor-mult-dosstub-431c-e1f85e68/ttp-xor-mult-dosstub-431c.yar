rule TTP_XOR_MULT_DOSStub_431c {
  strings:
    $key_431c = { 17 74 [2] 63 6c [2] 24 6e [2] 63 7f [2] 2d 73 [2] 21 79 [2] 36 72 [2] 2d 3c [2] 10 }

  condition:
    any of them
}