rule TTP_XOR_MULT_DOSStub_c5ad {
  strings:
    $key_c5ad = { 91 c5 [2] e5 dd [2] a2 df [2] e5 ce [2] ab c2 [2] a7 c8 [2] b0 c3 [2] ab 8d [2] 96 }

  condition:
    any of them
}