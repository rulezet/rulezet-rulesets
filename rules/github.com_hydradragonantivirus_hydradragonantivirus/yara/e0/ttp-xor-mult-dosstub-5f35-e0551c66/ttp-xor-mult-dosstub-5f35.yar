rule TTP_XOR_MULT_DOSStub_5f35 {
  strings:
    $key_5f35 = { 0b 5d [2] 7f 45 [2] 38 47 [2] 7f 56 [2] 31 5a [2] 3d 50 [2] 2a 5b [2] 31 15 [2] 0c }

  condition:
    any of them
}