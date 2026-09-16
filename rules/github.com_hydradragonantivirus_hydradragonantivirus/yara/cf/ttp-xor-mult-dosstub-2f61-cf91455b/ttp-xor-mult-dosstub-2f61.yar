rule TTP_XOR_MULT_DOSStub_2f61 {
  strings:
    $key_2f61 = { 7b 09 [2] 0f 11 [2] 48 13 [2] 0f 02 [2] 41 0e [2] 4d 04 [2] 5a 0f [2] 41 41 [2] 7c }

  condition:
    any of them
}