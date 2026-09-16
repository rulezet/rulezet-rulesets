rule TTP_XOR_MULT_DOSStub_3ef5 {
  strings:
    $key_3ef5 = { 6a 9d [2] 1e 85 [2] 59 87 [2] 1e 96 [2] 50 9a [2] 5c 90 [2] 4b 9b [2] 50 d5 [2] 6d }

  condition:
    any of them
}