rule TTP_XOR_MULT_DOSStub_5bf5 {
  strings:
    $key_5bf5 = { 0f 9d [2] 7b 85 [2] 3c 87 [2] 7b 96 [2] 35 9a [2] 39 90 [2] 2e 9b [2] 35 d5 [2] 08 }

  condition:
    any of them
}