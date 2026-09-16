rule TTP_XOR_MULT_DOSStub_51af {
  strings:
    $key_51af = { 05 c7 [2] 71 df [2] 36 dd [2] 71 cc [2] 3f c0 [2] 33 ca [2] 24 c1 [2] 3f 8f [2] 02 }

  condition:
    any of them
}