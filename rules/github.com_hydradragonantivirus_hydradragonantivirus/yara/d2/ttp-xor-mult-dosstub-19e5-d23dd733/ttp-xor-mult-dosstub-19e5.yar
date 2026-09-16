rule TTP_XOR_MULT_DOSStub_19e5 {
  strings:
    $key_19e5 = { 4d 8d [2] 39 95 [2] 7e 97 [2] 39 86 [2] 77 8a [2] 7b 80 [2] 6c 8b [2] 77 c5 [2] 4a }

  condition:
    any of them
}