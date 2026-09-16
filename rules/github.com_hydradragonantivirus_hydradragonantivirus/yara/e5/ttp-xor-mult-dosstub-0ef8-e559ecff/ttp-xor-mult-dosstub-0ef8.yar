rule TTP_XOR_MULT_DOSStub_0ef8 {
  strings:
    $key_0ef8 = { 5a 90 [2] 2e 88 [2] 69 8a [2] 2e 9b [2] 60 97 [2] 6c 9d [2] 7b 96 [2] 60 d8 [2] 5d }

  condition:
    any of them
}