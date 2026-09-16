rule TTP_XOR_MULT_DOSStub_ad90 {
  strings:
    $key_ad90 = { f9 f8 [2] 8d e0 [2] ca e2 [2] 8d f3 [2] c3 ff [2] cf f5 [2] d8 fe [2] c3 b0 [2] fe }

  condition:
    any of them
}