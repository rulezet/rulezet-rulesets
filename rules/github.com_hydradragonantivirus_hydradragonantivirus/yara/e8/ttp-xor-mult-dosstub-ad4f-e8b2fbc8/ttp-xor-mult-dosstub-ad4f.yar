rule TTP_XOR_MULT_DOSStub_ad4f {
  strings:
    $key_ad4f = { f9 27 [2] 8d 3f [2] ca 3d [2] 8d 2c [2] c3 20 [2] cf 2a [2] d8 21 [2] c3 6f [2] fe }

  condition:
    any of them
}