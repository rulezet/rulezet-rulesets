rule TTP_XOR_MULT_DOSStub_2932 {
  strings:
    $key_2932 = { 7d 5a [2] 09 42 [2] 4e 40 [2] 09 51 [2] 47 5d [2] 4b 57 [2] 5c 5c [2] 47 12 [2] 7a }

  condition:
    any of them
}