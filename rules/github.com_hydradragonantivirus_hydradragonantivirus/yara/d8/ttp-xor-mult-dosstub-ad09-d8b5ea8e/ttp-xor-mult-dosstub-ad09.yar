rule TTP_XOR_MULT_DOSStub_ad09 {
  strings:
    $key_ad09 = { f9 61 [2] 8d 79 [2] ca 7b [2] 8d 6a [2] c3 66 [2] cf 6c [2] d8 67 [2] c3 29 [2] fe }

  condition:
    any of them
}