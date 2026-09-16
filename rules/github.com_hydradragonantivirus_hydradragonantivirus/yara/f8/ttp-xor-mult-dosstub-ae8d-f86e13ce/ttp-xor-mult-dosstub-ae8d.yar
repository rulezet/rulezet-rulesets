rule TTP_XOR_MULT_DOSStub_ae8d {
  strings:
    $key_ae8d = { fa e5 [2] 8e fd [2] c9 ff [2] 8e ee [2] c0 e2 [2] cc e8 [2] db e3 [2] c0 ad [2] fd }

  condition:
    any of them
}