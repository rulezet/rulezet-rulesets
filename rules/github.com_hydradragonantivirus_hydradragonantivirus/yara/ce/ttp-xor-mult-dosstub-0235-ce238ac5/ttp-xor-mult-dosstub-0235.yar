rule TTP_XOR_MULT_DOSStub_0235 {
  strings:
    $key_0235 = { 56 5d [2] 22 45 [2] 65 47 [2] 22 56 [2] 6c 5a [2] 60 50 [2] 77 5b [2] 6c 15 [2] 51 }

  condition:
    any of them
}