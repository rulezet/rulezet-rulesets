rule TTP_XOR_MULT_DOSStub_f5ad {
  strings:
    $key_f5ad = { a1 c5 [2] d5 dd [2] 92 df [2] d5 ce [2] 9b c2 [2] 97 c8 [2] 80 c3 [2] 9b 8d [2] a6 }

  condition:
    any of them
}