rule TTP_XOR_MULT_DOSStub_ddaf {
  strings:
    $key_ddaf = { 89 c7 [2] fd df [2] ba dd [2] fd cc [2] b3 c0 [2] bf ca [2] a8 c1 [2] b3 8f [2] 8e }

  condition:
    any of them
}