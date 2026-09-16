rule TTP_XOR_MULT_DOSStub_ad29 {
  strings:
    $key_ad29 = { f9 41 [2] 8d 59 [2] ca 5b [2] 8d 4a [2] c3 46 [2] cf 4c [2] d8 47 [2] c3 09 [2] fe }

  condition:
    any of them
}