rule TTP_XOR_MULT_DOSStub_2f7c {
  strings:
    $key_2f7c = { 7b 14 [2] 0f 0c [2] 48 0e [2] 0f 1f [2] 41 13 [2] 4d 19 [2] 5a 12 [2] 41 5c [2] 7c }

  condition:
    any of them
}