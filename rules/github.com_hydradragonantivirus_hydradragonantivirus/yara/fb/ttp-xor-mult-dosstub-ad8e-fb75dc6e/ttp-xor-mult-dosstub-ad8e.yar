rule TTP_XOR_MULT_DOSStub_ad8e {
  strings:
    $key_ad8e = { f9 e6 [2] 8d fe [2] ca fc [2] 8d ed [2] c3 e1 [2] cf eb [2] d8 e0 [2] c3 ae [2] fe }

  condition:
    any of them
}