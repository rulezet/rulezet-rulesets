rule TTP_XOR_MULT_DOSStub_5b1c {
  strings:
    $key_5b1c = { 0f 74 [2] 7b 6c [2] 3c 6e [2] 7b 7f [2] 35 73 [2] 39 79 [2] 2e 72 [2] 35 3c [2] 08 }

  condition:
    any of them
}