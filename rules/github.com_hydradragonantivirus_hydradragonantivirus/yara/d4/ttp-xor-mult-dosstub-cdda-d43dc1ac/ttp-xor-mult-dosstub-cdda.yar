rule TTP_XOR_MULT_DOSStub_cdda {
  strings:
    $key_cdda = { 99 b2 [2] ed aa [2] aa a8 [2] ed b9 [2] a3 b5 [2] af bf [2] b8 b4 [2] a3 fa [2] 9e }

  condition:
    any of them
}