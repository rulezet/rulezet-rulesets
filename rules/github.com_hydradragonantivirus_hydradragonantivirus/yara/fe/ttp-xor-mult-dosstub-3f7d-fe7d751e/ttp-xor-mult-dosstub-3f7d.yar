rule TTP_XOR_MULT_DOSStub_3f7d {
  strings:
    $key_3f7d = { 6b 15 [2] 1f 0d [2] 58 0f [2] 1f 1e [2] 51 12 [2] 5d 18 [2] 4a 13 [2] 51 5d [2] 6c }

  condition:
    any of them
}