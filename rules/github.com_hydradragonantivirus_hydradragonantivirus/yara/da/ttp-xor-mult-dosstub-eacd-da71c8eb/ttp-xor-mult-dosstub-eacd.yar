rule TTP_XOR_MULT_DOSStub_eacd {
  strings:
    $key_eacd = { be a5 [2] ca bd [2] 8d bf [2] ca ae [2] 84 a2 [2] 88 a8 [2] 9f a3 [2] 84 ed [2] b9 }

  condition:
    any of them
}