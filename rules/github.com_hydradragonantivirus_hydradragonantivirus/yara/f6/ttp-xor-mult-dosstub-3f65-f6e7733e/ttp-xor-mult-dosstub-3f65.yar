rule TTP_XOR_MULT_DOSStub_3f65 {
  strings:
    $key_3f65 = { 6b 0d [2] 1f 15 [2] 58 17 [2] 1f 06 [2] 51 0a [2] 5d 00 [2] 4a 0b [2] 51 45 [2] 6c }

  condition:
    any of them
}