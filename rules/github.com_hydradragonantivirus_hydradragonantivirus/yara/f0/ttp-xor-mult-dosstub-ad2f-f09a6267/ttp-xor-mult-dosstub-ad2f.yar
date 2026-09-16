rule TTP_XOR_MULT_DOSStub_ad2f {
  strings:
    $key_ad2f = { f9 47 [2] 8d 5f [2] ca 5d [2] 8d 4c [2] c3 40 [2] cf 4a [2] d8 41 [2] c3 0f [2] fe }

  condition:
    any of them
}