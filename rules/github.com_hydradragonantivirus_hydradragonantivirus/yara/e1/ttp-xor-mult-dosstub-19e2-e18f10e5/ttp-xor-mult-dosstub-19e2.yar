rule TTP_XOR_MULT_DOSStub_19e2 {
  strings:
    $key_19e2 = { 4d 8a [2] 39 92 [2] 7e 90 [2] 39 81 [2] 77 8d [2] 7b 87 [2] 6c 8c [2] 77 c2 [2] 4a }

  condition:
    any of them
}