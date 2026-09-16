rule TTP_XOR_MULT_DOSStub_adaf {
  strings:
    $key_adaf = { f9 c7 [2] 8d df [2] ca dd [2] 8d cc [2] c3 c0 [2] cf ca [2] d8 c1 [2] c3 8f [2] fe }

  condition:
    any of them
}