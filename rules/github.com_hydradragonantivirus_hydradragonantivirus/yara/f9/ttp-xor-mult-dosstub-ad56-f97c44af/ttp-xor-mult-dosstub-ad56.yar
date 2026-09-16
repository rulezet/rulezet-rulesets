rule TTP_XOR_MULT_DOSStub_ad56 {
  strings:
    $key_ad56 = { f9 3e [2] 8d 26 [2] ca 24 [2] 8d 35 [2] c3 39 [2] cf 33 [2] d8 38 [2] c3 76 [2] fe }

  condition:
    any of them
}