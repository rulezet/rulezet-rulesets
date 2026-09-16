rule TTP_XOR_MULT_DOSStub_dd63 {
  strings:
    $key_dd63 = { 89 0b [2] fd 13 [2] ba 11 [2] fd 00 [2] b3 0c [2] bf 06 [2] a8 0d [2] b3 43 [2] 8e }

  condition:
    any of them
}