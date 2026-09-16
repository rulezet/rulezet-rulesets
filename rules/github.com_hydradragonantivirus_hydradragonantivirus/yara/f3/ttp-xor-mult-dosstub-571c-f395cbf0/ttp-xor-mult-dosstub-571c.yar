rule TTP_XOR_MULT_DOSStub_571c {
  strings:
    $key_571c = { 03 74 [2] 77 6c [2] 30 6e [2] 77 7f [2] 39 73 [2] 35 79 [2] 22 72 [2] 39 3c [2] 04 }

  condition:
    any of them
}