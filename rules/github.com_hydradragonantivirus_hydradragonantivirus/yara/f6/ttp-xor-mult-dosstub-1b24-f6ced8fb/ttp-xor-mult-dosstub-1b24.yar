rule TTP_XOR_MULT_DOSStub_1b24 {
  strings:
    $key_1b24 = { 4f 4c [2] 3b 54 [2] 7c 56 [2] 3b 47 [2] 75 4b [2] 79 41 [2] 6e 4a [2] 75 04 [2] 48 }

  condition:
    any of them
}