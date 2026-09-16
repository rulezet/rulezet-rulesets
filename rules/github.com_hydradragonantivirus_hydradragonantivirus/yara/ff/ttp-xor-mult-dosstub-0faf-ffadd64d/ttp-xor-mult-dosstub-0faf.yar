rule TTP_XOR_MULT_DOSStub_0faf {
  strings:
    $key_0faf = { 5b c7 [2] 2f df [2] 68 dd [2] 2f cc [2] 61 c0 [2] 6d ca [2] 7a c1 [2] 61 8f [2] 5c }

  condition:
    any of them
}