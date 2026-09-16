rule TTP_XOR_MULT_DOSStub_ad8d {
  strings:
    $key_ad8d = { f9 e5 [2] 8d fd [2] ca ff [2] 8d ee [2] c3 e2 [2] cf e8 [2] d8 e3 [2] c3 ad [2] fe }

  condition:
    any of them
}