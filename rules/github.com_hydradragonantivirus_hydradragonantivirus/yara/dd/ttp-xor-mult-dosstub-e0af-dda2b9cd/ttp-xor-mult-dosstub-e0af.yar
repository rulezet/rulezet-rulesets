rule TTP_XOR_MULT_DOSStub_e0af {
  strings:
    $key_e0af = { b4 c7 [2] c0 df [2] 87 dd [2] c0 cc [2] 8e c0 [2] 82 ca [2] 95 c1 [2] 8e 8f [2] b3 }

  condition:
    any of them
}