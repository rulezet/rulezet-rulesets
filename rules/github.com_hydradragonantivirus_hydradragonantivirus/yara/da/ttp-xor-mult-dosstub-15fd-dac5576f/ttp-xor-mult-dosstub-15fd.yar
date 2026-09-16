rule TTP_XOR_MULT_DOSStub_15fd {
  strings:
    $key_15fd = { 41 95 [2] 35 8d [2] 72 8f [2] 35 9e [2] 7b 92 [2] 77 98 [2] 60 93 [2] 7b dd [2] 46 }

  condition:
    any of them
}