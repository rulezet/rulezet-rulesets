rule TTP_XOR_MULT_DOSStub_24fd {
  strings:
    $key_24fd = { 70 95 [2] 04 8d [2] 43 8f [2] 04 9e [2] 4a 92 [2] 46 98 [2] 51 93 [2] 4a dd [2] 77 }

  condition:
    any of them
}