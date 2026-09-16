rule TTP_XOR_MULT_DOSStub_6685 {
  strings:
    $key_6685 = { 32 ed [2] 46 f5 [2] 01 f7 [2] 46 e6 [2] 08 ea [2] 04 e0 [2] 13 eb [2] 08 a5 [2] 35 }

  condition:
    any of them
}