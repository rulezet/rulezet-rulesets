rule TTP_XOR_MULT_DOSStub_1910 {
  strings:
    $key_1910 = { 4d 78 [2] 39 60 [2] 7e 62 [2] 39 73 [2] 77 7f [2] 7b 75 [2] 6c 7e [2] 77 30 [2] 4a }

  condition:
    any of them
}