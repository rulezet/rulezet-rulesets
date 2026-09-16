rule TTP_XOR_MULT_DOSStub_2f10 {
  strings:
    $key_2f10 = { 7b 78 [2] 0f 60 [2] 48 62 [2] 0f 73 [2] 41 7f [2] 4d 75 [2] 5a 7e [2] 41 30 [2] 7c }

  condition:
    any of them
}