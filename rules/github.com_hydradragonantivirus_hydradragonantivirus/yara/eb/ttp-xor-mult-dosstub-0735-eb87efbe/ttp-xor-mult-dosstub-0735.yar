rule TTP_XOR_MULT_DOSStub_0735 {
  strings:
    $key_0735 = { 53 5d [2] 27 45 [2] 60 47 [2] 27 56 [2] 69 5a [2] 65 50 [2] 72 5b [2] 69 15 [2] 54 }

  condition:
    any of them
}