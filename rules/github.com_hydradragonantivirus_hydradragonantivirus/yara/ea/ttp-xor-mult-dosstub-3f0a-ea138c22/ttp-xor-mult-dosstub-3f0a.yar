rule TTP_XOR_MULT_DOSStub_3f0a {
  strings:
    $key_3f0a = { 6b 62 [2] 1f 7a [2] 58 78 [2] 1f 69 [2] 51 65 [2] 5d 6f [2] 4a 64 [2] 51 2a [2] 6c }

  condition:
    any of them
}