rule TTP_XOR_MULT_DOSStub_ad6a {
  strings:
    $key_ad6a = { f9 02 [2] 8d 1a [2] ca 18 [2] 8d 09 [2] c3 05 [2] cf 0f [2] d8 04 [2] c3 4a [2] fe }

  condition:
    any of them
}