rule TTP_XOR_MULT_DOSStub_65fd {
  strings:
    $key_65fd = { 31 95 [2] 45 8d [2] 02 8f [2] 45 9e [2] 0b 92 [2] 07 98 [2] 10 93 [2] 0b dd [2] 36 }

  condition:
    any of them
}