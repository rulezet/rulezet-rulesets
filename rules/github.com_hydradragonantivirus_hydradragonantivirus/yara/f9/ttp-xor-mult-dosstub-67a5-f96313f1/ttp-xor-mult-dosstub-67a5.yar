rule TTP_XOR_MULT_DOSStub_67a5 {
  strings:
    $key_67a5 = { 33 cd [2] 47 d5 [2] 00 d7 [2] 47 c6 [2] 09 ca [2] 05 c0 [2] 12 cb [2] 09 85 [2] 34 }

  condition:
    any of them
}