rule TTP_XOR_MULT_DOSStub_ad01 {
  strings:
    $key_ad01 = { f9 69 [2] 8d 71 [2] ca 73 [2] 8d 62 [2] c3 6e [2] cf 64 [2] d8 6f [2] c3 21 [2] fe }

  condition:
    any of them
}