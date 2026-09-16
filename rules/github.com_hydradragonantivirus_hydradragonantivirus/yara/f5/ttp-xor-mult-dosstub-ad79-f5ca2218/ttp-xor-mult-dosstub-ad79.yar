rule TTP_XOR_MULT_DOSStub_ad79 {
  strings:
    $key_ad79 = { f9 11 [2] 8d 09 [2] ca 0b [2] 8d 1a [2] c3 16 [2] cf 1c [2] d8 17 [2] c3 59 [2] fe }

  condition:
    any of them
}