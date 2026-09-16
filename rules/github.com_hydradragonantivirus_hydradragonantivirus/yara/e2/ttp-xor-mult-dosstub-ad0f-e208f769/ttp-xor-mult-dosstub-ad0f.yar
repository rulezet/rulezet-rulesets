rule TTP_XOR_MULT_DOSStub_ad0f {
  strings:
    $key_ad0f = { f9 67 [2] 8d 7f [2] ca 7d [2] 8d 6c [2] c3 60 [2] cf 6a [2] d8 61 [2] c3 2f [2] fe }

  condition:
    any of them
}