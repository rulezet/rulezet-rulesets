rule TTP_XOR_MULT_DOSStub_1916 {
  strings:
    $key_1916 = { 4d 7e [2] 39 66 [2] 7e 64 [2] 39 75 [2] 77 79 [2] 7b 73 [2] 6c 78 [2] 77 36 [2] 4a }

  condition:
    any of them
}