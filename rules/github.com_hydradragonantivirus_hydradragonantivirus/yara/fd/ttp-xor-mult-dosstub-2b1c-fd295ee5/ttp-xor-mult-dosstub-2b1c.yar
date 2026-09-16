rule TTP_XOR_MULT_DOSStub_2b1c {
  strings:
    $key_2b1c = { 7f 74 [2] 0b 6c [2] 4c 6e [2] 0b 7f [2] 45 73 [2] 49 79 [2] 5e 72 [2] 45 3c [2] 78 }

  condition:
    any of them
}