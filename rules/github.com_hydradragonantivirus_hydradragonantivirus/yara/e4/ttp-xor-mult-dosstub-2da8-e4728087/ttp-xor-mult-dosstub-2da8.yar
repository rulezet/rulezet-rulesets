rule TTP_XOR_MULT_DOSStub_2da8 {
  strings:
    $key_2da8 = { 79 c0 [2] 0d d8 [2] 4a da [2] 0d cb [2] 43 c7 [2] 4f cd [2] 58 c6 [2] 43 88 [2] 7e }

  condition:
    any of them
}