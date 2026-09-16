rule TTP_XOR_MULT_DOSStub_0bcd {
  strings:
    $key_0bcd = { 5f a5 [2] 2b bd [2] 6c bf [2] 2b ae [2] 65 a2 [2] 69 a8 [2] 7e a3 [2] 65 ed [2] 58 }

  condition:
    any of them
}