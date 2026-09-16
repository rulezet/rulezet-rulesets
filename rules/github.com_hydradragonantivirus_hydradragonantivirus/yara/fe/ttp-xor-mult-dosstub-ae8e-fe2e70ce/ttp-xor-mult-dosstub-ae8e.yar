rule TTP_XOR_MULT_DOSStub_ae8e {
  strings:
    $key_ae8e = { fa e6 [2] 8e fe [2] c9 fc [2] 8e ed [2] c0 e1 [2] cc eb [2] db e0 [2] c0 ae [2] fd }

  condition:
    any of them
}