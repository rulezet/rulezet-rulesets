rule TTP_XOR_MULT_DOSStub_3412 {
  strings:
    $key_3412 = { 60 7a [2] 14 62 [2] 53 60 [2] 14 71 [2] 5a 7d [2] 56 77 [2] 41 7c [2] 5a 32 [2] 67 }

  condition:
    any of them
}