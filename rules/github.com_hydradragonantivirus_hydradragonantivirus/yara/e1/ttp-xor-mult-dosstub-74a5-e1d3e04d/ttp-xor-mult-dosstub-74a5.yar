rule TTP_XOR_MULT_DOSStub_74a5 {
  strings:
    $key_74a5 = { 20 cd [2] 54 d5 [2] 13 d7 [2] 54 c6 [2] 1a ca [2] 16 c0 [2] 01 cb [2] 1a 85 [2] 27 }

  condition:
    any of them
}