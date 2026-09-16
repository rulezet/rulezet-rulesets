rule TTP_XOR_MULT_DOSStub_5924 {
  strings:
    $key_5924 = { 0d 4c [2] 79 54 [2] 3e 56 [2] 79 47 [2] 37 4b [2] 3b 41 [2] 2c 4a [2] 37 04 [2] 0a }

  condition:
    any of them
}