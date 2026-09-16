rule TTP_XOR_MULT_DOSStub_0239 {
  strings:
    $key_0239 = { 56 51 [2] 22 49 [2] 65 4b [2] 22 5a [2] 6c 56 [2] 60 5c [2] 77 57 [2] 6c 19 [2] 51 }

  condition:
    any of them
}