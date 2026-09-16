rule TTP_XOR_MULT_DOSStub_66ba {
  strings:
    $key_66ba = { 32 d2 [2] 46 ca [2] 01 c8 [2] 46 d9 [2] 08 d5 [2] 04 df [2] 13 d4 [2] 08 9a [2] 35 }

  condition:
    any of them
}