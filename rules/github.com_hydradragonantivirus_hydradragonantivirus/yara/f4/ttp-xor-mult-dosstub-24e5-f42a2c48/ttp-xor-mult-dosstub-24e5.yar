rule TTP_XOR_MULT_DOSStub_24e5 {
  strings:
    $key_24e5 = { 70 8d [2] 04 95 [2] 43 97 [2] 04 86 [2] 4a 8a [2] 46 80 [2] 51 8b [2] 4a c5 [2] 77 }

  condition:
    any of them
}