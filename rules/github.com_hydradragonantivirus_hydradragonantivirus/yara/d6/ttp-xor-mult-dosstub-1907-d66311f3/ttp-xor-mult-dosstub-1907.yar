rule TTP_XOR_MULT_DOSStub_1907 {
  strings:
    $key_1907 = { 4d 6f [2] 39 77 [2] 7e 75 [2] 39 64 [2] 77 68 [2] 7b 62 [2] 6c 69 [2] 77 27 [2] 4a }

  condition:
    any of them
}