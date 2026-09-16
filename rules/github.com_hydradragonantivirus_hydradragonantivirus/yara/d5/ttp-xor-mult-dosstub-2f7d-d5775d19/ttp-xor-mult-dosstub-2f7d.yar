rule TTP_XOR_MULT_DOSStub_2f7d {
  strings:
    $key_2f7d = { 7b 15 [2] 0f 0d [2] 48 0f [2] 0f 1e [2] 41 12 [2] 4d 18 [2] 5a 13 [2] 41 5d [2] 7c }

  condition:
    any of them
}