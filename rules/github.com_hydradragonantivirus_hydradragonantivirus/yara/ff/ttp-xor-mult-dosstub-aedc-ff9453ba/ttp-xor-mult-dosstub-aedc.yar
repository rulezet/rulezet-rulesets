rule TTP_XOR_MULT_DOSStub_aedc {
  strings:
    $key_aedc = { fa b4 [2] 8e ac [2] c9 ae [2] 8e bf [2] c0 b3 [2] cc b9 [2] db b2 [2] c0 fc [2] fd }

  condition:
    any of them
}