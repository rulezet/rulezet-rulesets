rule TTP_XOR_MULT_DOSStub_2ef8 {
  strings:
    $key_2ef8 = { 7a 90 [2] 0e 88 [2] 49 8a [2] 0e 9b [2] 40 97 [2] 4c 9d [2] 5b 96 [2] 40 d8 [2] 7d }

  condition:
    any of them
}