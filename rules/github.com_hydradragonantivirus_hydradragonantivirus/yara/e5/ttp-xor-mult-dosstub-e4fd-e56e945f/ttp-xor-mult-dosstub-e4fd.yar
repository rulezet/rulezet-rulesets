rule TTP_XOR_MULT_DOSStub_e4fd {
  strings:
    $key_e4fd = { b0 95 [2] c4 8d [2] 83 8f [2] c4 9e [2] 8a 92 [2] 86 98 [2] 91 93 [2] 8a dd [2] b7 }

  condition:
    any of them
}