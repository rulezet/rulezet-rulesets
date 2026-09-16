rule TTP_XOR_MULT_DOSStub_ad00 {
  strings:
    $key_ad00 = { f9 68 [2] 8d 70 [2] ca 72 [2] 8d 63 [2] c3 6f [2] cf 65 [2] d8 6e [2] c3 20 [2] fe }

  condition:
    any of them
}