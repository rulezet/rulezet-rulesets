rule TTP_XOR_MULT_DOSStub_19e8 {
  strings:
    $key_19e8 = { 4d 80 [2] 39 98 [2] 7e 9a [2] 39 8b [2] 77 87 [2] 7b 8d [2] 6c 86 [2] 77 c8 [2] 4a }

  condition:
    any of them
}