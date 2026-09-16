rule TTP_XOR_MULT_DOSStub_65af {
  strings:
    $key_65af = { 31 c7 [2] 45 df [2] 02 dd [2] 45 cc [2] 0b c0 [2] 07 ca [2] 10 c1 [2] 0b 8f [2] 36 }

  condition:
    any of them
}