rule TTP_XOR_MULT_DOSStub_74af {
  strings:
    $key_74af = { 20 c7 [2] 54 df [2] 13 dd [2] 54 cc [2] 1a c0 [2] 16 ca [2] 01 c1 [2] 1a 8f [2] 27 }

  condition:
    any of them
}