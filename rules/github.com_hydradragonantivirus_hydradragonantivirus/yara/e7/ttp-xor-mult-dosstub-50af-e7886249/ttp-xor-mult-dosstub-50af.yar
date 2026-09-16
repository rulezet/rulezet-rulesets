rule TTP_XOR_MULT_DOSStub_50af {
  strings:
    $key_50af = { 04 c7 [2] 70 df [2] 37 dd [2] 70 cc [2] 3e c0 [2] 32 ca [2] 25 c1 [2] 3e 8f [2] 03 }

  condition:
    any of them
}