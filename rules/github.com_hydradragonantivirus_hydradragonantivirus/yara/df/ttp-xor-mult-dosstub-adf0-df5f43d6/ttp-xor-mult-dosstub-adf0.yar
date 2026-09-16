rule TTP_XOR_MULT_DOSStub_adf0 {
  strings:
    $key_adf0 = { f9 98 [2] 8d 80 [2] ca 82 [2] 8d 93 [2] c3 9f [2] cf 95 [2] d8 9e [2] c3 d0 [2] fe }

  condition:
    any of them
}