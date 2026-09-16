rule TTP_XOR_MULT_DOSStub_6faf {
  strings:
    $key_6faf = { 3b c7 [2] 4f df [2] 08 dd [2] 4f cc [2] 01 c0 [2] 0d ca [2] 1a c1 [2] 01 8f [2] 3c }

  condition:
    any of them
}