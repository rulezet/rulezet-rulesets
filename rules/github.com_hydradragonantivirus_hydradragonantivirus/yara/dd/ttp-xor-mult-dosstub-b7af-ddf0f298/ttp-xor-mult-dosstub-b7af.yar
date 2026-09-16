rule TTP_XOR_MULT_DOSStub_b7af {
  strings:
    $key_b7af = { e3 c7 [2] 97 df [2] d0 dd [2] 97 cc [2] d9 c0 [2] d5 ca [2] c2 c1 [2] d9 8f [2] e4 }

  condition:
    any of them
}