rule TTP_XOR_MULT_DOSStub_ad28 {
  strings:
    $key_ad28 = { f9 40 [2] 8d 58 [2] ca 5a [2] 8d 4b [2] c3 47 [2] cf 4d [2] d8 46 [2] c3 08 [2] fe }

  condition:
    any of them
}