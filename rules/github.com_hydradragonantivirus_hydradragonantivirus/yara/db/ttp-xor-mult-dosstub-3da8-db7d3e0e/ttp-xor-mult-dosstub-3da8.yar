rule TTP_XOR_MULT_DOSStub_3da8 {
  strings:
    $key_3da8 = { 69 c0 [2] 1d d8 [2] 5a da [2] 1d cb [2] 53 c7 [2] 5f cd [2] 48 c6 [2] 53 88 [2] 6e }

  condition:
    any of them
}