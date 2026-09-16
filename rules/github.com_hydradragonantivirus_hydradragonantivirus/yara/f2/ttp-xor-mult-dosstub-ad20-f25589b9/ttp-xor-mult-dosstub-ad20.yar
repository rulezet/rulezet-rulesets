rule TTP_XOR_MULT_DOSStub_ad20 {
  strings:
    $key_ad20 = { f9 48 [2] 8d 50 [2] ca 52 [2] 8d 43 [2] c3 4f [2] cf 45 [2] d8 4e [2] c3 00 [2] fe }

  condition:
    any of them
}