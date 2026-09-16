rule TTP_XOR_MULT_DOSStub_f0a5 {
  strings:
    $key_f0a5 = { a4 cd [2] d0 d5 [2] 97 d7 [2] d0 c6 [2] 9e ca [2] 92 c0 [2] 85 cb [2] 9e 85 [2] a3 }

  condition:
    any of them
}