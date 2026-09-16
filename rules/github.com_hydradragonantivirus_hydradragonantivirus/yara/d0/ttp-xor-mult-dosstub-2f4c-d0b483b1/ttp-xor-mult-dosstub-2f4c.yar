rule TTP_XOR_MULT_DOSStub_2f4c {
  strings:
    $key_2f4c = { 7b 24 [2] 0f 3c [2] 48 3e [2] 0f 2f [2] 41 23 [2] 4d 29 [2] 5a 22 [2] 41 6c [2] 7c }

  condition:
    any of them
}