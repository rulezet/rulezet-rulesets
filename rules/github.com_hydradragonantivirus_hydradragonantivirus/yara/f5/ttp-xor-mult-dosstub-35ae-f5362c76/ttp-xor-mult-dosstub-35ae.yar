rule TTP_XOR_MULT_DOSStub_35ae {
  strings:
    $key_35ae = { 61 c6 [2] 15 de [2] 52 dc [2] 15 cd [2] 5b c1 [2] 57 cb [2] 40 c0 [2] 5b 8e [2] 66 }

  condition:
    any of them
}