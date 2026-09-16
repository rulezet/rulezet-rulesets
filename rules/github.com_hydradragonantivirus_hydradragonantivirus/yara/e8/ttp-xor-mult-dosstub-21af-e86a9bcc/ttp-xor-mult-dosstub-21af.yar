rule TTP_XOR_MULT_DOSStub_21af {
  strings:
    $key_21af = { 75 c7 [2] 01 df [2] 46 dd [2] 01 cc [2] 4f c0 [2] 43 ca [2] 54 c1 [2] 4f 8f [2] 72 }

  condition:
    any of them
}