rule TTP_XOR_MULT_DOSStub_2ef5 {
  strings:
    $key_2ef5 = { 7a 9d [2] 0e 85 [2] 49 87 [2] 0e 96 [2] 40 9a [2] 4c 90 [2] 5b 9b [2] 40 d5 [2] 7d }

  condition:
    any of them
}