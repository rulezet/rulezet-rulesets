rule TTP_XOR_MULT_DOSStub_0935 {
  strings:
    $key_0935 = { 5d 5d [2] 29 45 [2] 6e 47 [2] 29 56 [2] 67 5a [2] 6b 50 [2] 7c 5b [2] 67 15 [2] 5a }

  condition:
    any of them
}