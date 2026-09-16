rule TTP_XOR_MULT_DOSStub_3faf {
  strings:
    $key_3faf = { 6b c7 [2] 1f df [2] 58 dd [2] 1f cc [2] 51 c0 [2] 5d ca [2] 4a c1 [2] 51 8f [2] 6c }

  condition:
    any of them
}