rule TTP_XOR_MULT_DOSStub_6f35 {
  strings:
    $key_6f35 = { 3b 5d [2] 4f 45 [2] 08 47 [2] 4f 56 [2] 01 5a [2] 0d 50 [2] 1a 5b [2] 01 15 [2] 3c }

  condition:
    any of them
}