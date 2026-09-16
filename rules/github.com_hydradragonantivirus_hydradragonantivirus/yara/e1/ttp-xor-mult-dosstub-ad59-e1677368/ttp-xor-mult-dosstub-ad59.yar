rule TTP_XOR_MULT_DOSStub_ad59 {
  strings:
    $key_ad59 = { f9 31 [2] 8d 29 [2] ca 2b [2] 8d 3a [2] c3 36 [2] cf 3c [2] d8 37 [2] c3 79 [2] fe }

  condition:
    any of them
}