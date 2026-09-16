rule TTP_XOR_MULT_DOSStub_197b {
  strings:
    $key_197b = { 4d 13 [2] 39 0b [2] 7e 09 [2] 39 18 [2] 77 14 [2] 7b 1e [2] 6c 15 [2] 77 5b [2] 4a }

  condition:
    any of them
}