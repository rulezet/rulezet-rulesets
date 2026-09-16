rule TTP_XOR_MULT_DOSStub_1925 {
  strings:
    $key_1925 = { 4d 4d [2] 39 55 [2] 7e 57 [2] 39 46 [2] 77 4a [2] 7b 40 [2] 6c 4b [2] 77 05 [2] 4a }

  condition:
    any of them
}