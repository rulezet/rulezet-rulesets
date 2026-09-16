rule TTP_XOR_MULT_DOSStub_ad13 {
  strings:
    $key_ad13 = { f9 7b [2] 8d 63 [2] ca 61 [2] 8d 70 [2] c3 7c [2] cf 76 [2] d8 7d [2] c3 33 [2] fe }

  condition:
    any of them
}