rule TTP_XOR_MULT_DOSStub_7e1c {
  strings:
    $key_7e1c = { 2a 74 [2] 5e 6c [2] 19 6e [2] 5e 7f [2] 10 73 [2] 1c 79 [2] 0b 72 [2] 10 3c [2] 2d }

  condition:
    any of them
}