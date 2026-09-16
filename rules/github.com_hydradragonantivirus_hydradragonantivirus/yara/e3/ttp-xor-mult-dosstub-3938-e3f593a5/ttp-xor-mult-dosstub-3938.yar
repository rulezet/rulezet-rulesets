rule TTP_XOR_MULT_DOSStub_3938 {
  strings:
    $key_3938 = { 6d 50 [2] 19 48 [2] 5e 4a [2] 19 5b [2] 57 57 [2] 5b 5d [2] 4c 56 [2] 57 18 [2] 6a }

  condition:
    any of them
}