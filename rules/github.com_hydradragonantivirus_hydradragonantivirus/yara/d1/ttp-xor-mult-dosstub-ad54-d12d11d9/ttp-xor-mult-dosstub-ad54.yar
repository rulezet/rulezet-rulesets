rule TTP_XOR_MULT_DOSStub_ad54 {
  strings:
    $key_ad54 = { f9 3c [2] 8d 24 [2] ca 26 [2] 8d 37 [2] c3 3b [2] cf 31 [2] d8 3a [2] c3 74 [2] fe }

  condition:
    any of them
}