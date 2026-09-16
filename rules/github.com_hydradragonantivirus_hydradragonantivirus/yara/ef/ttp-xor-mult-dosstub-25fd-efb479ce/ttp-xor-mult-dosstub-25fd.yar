rule TTP_XOR_MULT_DOSStub_25fd {
  strings:
    $key_25fd = { 71 95 [2] 05 8d [2] 42 8f [2] 05 9e [2] 4b 92 [2] 47 98 [2] 50 93 [2] 4b dd [2] 76 }

  condition:
    any of them
}