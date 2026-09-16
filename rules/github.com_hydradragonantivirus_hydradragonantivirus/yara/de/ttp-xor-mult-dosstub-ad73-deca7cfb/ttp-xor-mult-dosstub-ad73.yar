rule TTP_XOR_MULT_DOSStub_ad73 {
  strings:
    $key_ad73 = { f9 1b [2] 8d 03 [2] ca 01 [2] 8d 10 [2] c3 1c [2] cf 16 [2] d8 1d [2] c3 53 [2] fe }

  condition:
    any of them
}