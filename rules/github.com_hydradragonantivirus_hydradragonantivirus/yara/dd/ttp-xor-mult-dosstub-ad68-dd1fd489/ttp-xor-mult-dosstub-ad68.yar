rule TTP_XOR_MULT_DOSStub_ad68 {
  strings:
    $key_ad68 = { f9 00 [2] 8d 18 [2] ca 1a [2] 8d 0b [2] c3 07 [2] cf 0d [2] d8 06 [2] c3 48 [2] fe }

  condition:
    any of them
}