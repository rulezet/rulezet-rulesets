rule TTP_XOR_MULT_DOSStub_adfa {
  strings:
    $key_adfa = { f9 92 [2] 8d 8a [2] ca 88 [2] 8d 99 [2] c3 95 [2] cf 9f [2] d8 94 [2] c3 da [2] fe }

  condition:
    any of them
}