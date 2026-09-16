rule TTP_XOR_MULT_DOSStub_23fd {
  strings:
    $key_23fd = { 77 95 [2] 03 8d [2] 44 8f [2] 03 9e [2] 4d 92 [2] 41 98 [2] 56 93 [2] 4d dd [2] 70 }

  condition:
    any of them
}