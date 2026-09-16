rule TTP_XOR_MULT_DOSStub_e3af {
  strings:
    $key_e3af = { b7 c7 [2] c3 df [2] 84 dd [2] c3 cc [2] 8d c0 [2] 81 ca [2] 96 c1 [2] 8d 8f [2] b0 }

  condition:
    any of them
}