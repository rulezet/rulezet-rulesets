rule TTP_XOR_MULT_DOSStub_b9af {
  strings:
    $key_b9af = { ed c7 [2] 99 df [2] de dd [2] 99 cc [2] d7 c0 [2] db ca [2] cc c1 [2] d7 8f [2] ea }

  condition:
    any of them
}