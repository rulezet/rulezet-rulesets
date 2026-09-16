rule TTP_XOR_MULT_DOSStub_3f07 {
  strings:
    $key_3f07 = { 6b 6f [2] 1f 77 [2] 58 75 [2] 1f 64 [2] 51 68 [2] 5d 62 [2] 4a 69 [2] 51 27 [2] 6c }

  condition:
    any of them
}