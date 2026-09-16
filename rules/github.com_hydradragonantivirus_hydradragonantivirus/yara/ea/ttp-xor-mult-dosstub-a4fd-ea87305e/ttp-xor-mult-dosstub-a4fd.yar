rule TTP_XOR_MULT_DOSStub_a4fd {
  strings:
    $key_a4fd = { f0 95 [2] 84 8d [2] c3 8f [2] 84 9e [2] ca 92 [2] c6 98 [2] d1 93 [2] ca dd [2] f7 }

  condition:
    any of them
}