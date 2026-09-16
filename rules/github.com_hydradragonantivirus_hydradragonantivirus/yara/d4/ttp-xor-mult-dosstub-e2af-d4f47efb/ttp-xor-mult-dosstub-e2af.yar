rule TTP_XOR_MULT_DOSStub_e2af {
  strings:
    $key_e2af = { b6 c7 [2] c2 df [2] 85 dd [2] c2 cc [2] 8c c0 [2] 80 ca [2] 97 c1 [2] 8c 8f [2] b1 }

  condition:
    any of them
}