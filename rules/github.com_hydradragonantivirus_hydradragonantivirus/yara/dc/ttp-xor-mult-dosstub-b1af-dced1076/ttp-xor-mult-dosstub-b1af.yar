rule TTP_XOR_MULT_DOSStub_b1af {
  strings:
    $key_b1af = { e5 c7 [2] 91 df [2] d6 dd [2] 91 cc [2] df c0 [2] d3 ca [2] c4 c1 [2] df 8f [2] e2 }

  condition:
    any of them
}