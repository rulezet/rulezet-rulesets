rule TTP_XOR_MULT_DOSStub_ad8b {
  strings:
    $key_ad8b = { f9 e3 [2] 8d fb [2] ca f9 [2] 8d e8 [2] c3 e4 [2] cf ee [2] d8 e5 [2] c3 ab [2] fe }

  condition:
    any of them
}