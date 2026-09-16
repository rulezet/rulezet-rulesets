rule TTP_XOR_MULT_DOSStub_2eaf {
  strings:
    $key_2eaf = { 7a c7 [2] 0e df [2] 49 dd [2] 0e cc [2] 40 c0 [2] 4c ca [2] 5b c1 [2] 40 8f [2] 7d }

  condition:
    any of them
}