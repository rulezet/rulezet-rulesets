rule TTP_XOR_MULT_DOSStub_34a5 {
  strings:
    $key_34a5 = { 60 cd [2] 14 d5 [2] 53 d7 [2] 14 c6 [2] 5a ca [2] 56 c0 [2] 41 cb [2] 5a 85 [2] 67 }

  condition:
    any of them
}