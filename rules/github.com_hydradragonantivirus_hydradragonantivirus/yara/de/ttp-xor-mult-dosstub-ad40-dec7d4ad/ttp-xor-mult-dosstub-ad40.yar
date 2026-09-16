rule TTP_XOR_MULT_DOSStub_ad40 {
  strings:
    $key_ad40 = { f9 28 [2] 8d 30 [2] ca 32 [2] 8d 23 [2] c3 2f [2] cf 25 [2] d8 2e [2] c3 60 [2] fe }

  condition:
    any of them
}