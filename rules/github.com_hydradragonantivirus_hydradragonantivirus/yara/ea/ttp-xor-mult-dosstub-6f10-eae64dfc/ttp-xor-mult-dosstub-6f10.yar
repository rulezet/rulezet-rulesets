rule TTP_XOR_MULT_DOSStub_6f10 {
  strings:
    $key_6f10 = { 3b 78 [2] 4f 60 [2] 08 62 [2] 4f 73 [2] 01 7f [2] 0d 75 [2] 1a 7e [2] 01 30 [2] 3c }

  condition:
    any of them
}