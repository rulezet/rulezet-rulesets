rule TTP_XOR_MULT_DOSStub_2f70 {
  strings:
    $key_2f70 = { 7b 18 [2] 0f 00 [2] 48 02 [2] 0f 13 [2] 41 1f [2] 4d 15 [2] 5a 1e [2] 41 50 [2] 7c }

  condition:
    any of them
}