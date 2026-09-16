rule TTP_XOR_MULT_DOSStub_ad25 {
  strings:
    $key_ad25 = { f9 4d [2] 8d 55 [2] ca 57 [2] 8d 46 [2] c3 4a [2] cf 40 [2] d8 4b [2] c3 05 [2] fe }

  condition:
    any of them
}