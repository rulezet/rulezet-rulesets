rule TTP_XOR_MULT_DOSStub_0524 {
  strings:
    $key_0524 = { 51 4c [2] 25 54 [2] 62 56 [2] 25 47 [2] 6b 4b [2] 67 41 [2] 70 4a [2] 6b 04 [2] 56 }

  condition:
    any of them
}