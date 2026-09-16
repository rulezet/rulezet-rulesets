rule TTP_XOR_MULT_DOSStub_b1ad {
  strings:
    $key_b1ad = { e5 c5 [2] 91 dd [2] d6 df [2] 91 ce [2] df c2 [2] d3 c8 [2] c4 c3 [2] df 8d [2] e2 }

  condition:
    any of them
}