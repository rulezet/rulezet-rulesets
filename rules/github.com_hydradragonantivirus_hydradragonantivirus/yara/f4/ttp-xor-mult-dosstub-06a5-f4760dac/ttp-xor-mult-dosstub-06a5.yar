rule TTP_XOR_MULT_DOSStub_06a5 {
  strings:
    $key_06a5 = { 52 cd [2] 26 d5 [2] 61 d7 [2] 26 c6 [2] 68 ca [2] 64 c0 [2] 73 cb [2] 68 85 [2] 55 }

  condition:
    any of them
}