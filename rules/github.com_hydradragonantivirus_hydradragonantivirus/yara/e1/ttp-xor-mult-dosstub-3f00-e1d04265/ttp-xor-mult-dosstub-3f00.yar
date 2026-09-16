rule TTP_XOR_MULT_DOSStub_3f00 {
  strings:
    $key_3f00 = { 6b 68 [2] 1f 70 [2] 58 72 [2] 1f 63 [2] 51 6f [2] 5d 65 [2] 4a 6e [2] 51 20 [2] 6c }

  condition:
    any of them
}