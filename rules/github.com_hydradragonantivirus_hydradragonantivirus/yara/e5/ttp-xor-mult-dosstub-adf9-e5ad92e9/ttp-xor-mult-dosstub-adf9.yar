rule TTP_XOR_MULT_DOSStub_adf9 {
  strings:
    $key_adf9 = { f9 91 [2] 8d 89 [2] ca 8b [2] 8d 9a [2] c3 96 [2] cf 9c [2] d8 97 [2] c3 d9 [2] fe }

  condition:
    any of them
}