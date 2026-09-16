rule TTP_XOR_MULT_DOSStub_6f0a {
  strings:
    $key_6f0a = { 3b 62 [2] 4f 7a [2] 08 78 [2] 4f 69 [2] 01 65 [2] 0d 6f [2] 1a 64 [2] 01 2a [2] 3c }

  condition:
    any of them
}