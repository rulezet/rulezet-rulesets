rule TTP_XOR_MULT_DOSStub_4cf5 {
  strings:
    $key_4cf5 = { 18 9d [2] 6c 85 [2] 2b 87 [2] 6c 96 [2] 22 9a [2] 2e 90 [2] 39 9b [2] 22 d5 [2] 1f }

  condition:
    any of them
}