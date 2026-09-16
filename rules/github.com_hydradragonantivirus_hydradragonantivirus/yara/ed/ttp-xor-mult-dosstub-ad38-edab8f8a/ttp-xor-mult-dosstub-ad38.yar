rule TTP_XOR_MULT_DOSStub_ad38 {
  strings:
    $key_ad38 = { f9 50 [2] 8d 48 [2] ca 4a [2] 8d 5b [2] c3 57 [2] cf 5d [2] d8 56 [2] c3 18 [2] fe }

  condition:
    any of them
}