rule TTP_XOR_MULT_DOSStub_63fd {
  strings:
    $key_63fd = { 37 95 [2] 43 8d [2] 04 8f [2] 43 9e [2] 0d 92 [2] 01 98 [2] 16 93 [2] 0d dd [2] 30 }

  condition:
    any of them
}