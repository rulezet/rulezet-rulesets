rule TTP_XOR_MULT_DOSStub_5a1c {
  strings:
    $key_5a1c = { 0e 74 [2] 7a 6c [2] 3d 6e [2] 7a 7f [2] 34 73 [2] 38 79 [2] 2f 72 [2] 34 3c [2] 09 }

  condition:
    any of them
}