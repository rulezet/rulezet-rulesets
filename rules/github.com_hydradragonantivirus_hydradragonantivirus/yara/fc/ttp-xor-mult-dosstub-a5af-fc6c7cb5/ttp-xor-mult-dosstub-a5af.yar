rule TTP_XOR_MULT_DOSStub_a5af {
  strings:
    $key_a5af = { f1 c7 [2] 85 df [2] c2 dd [2] 85 cc [2] cb c0 [2] c7 ca [2] d0 c1 [2] cb 8f [2] f6 }

  condition:
    any of them
}