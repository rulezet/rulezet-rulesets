rule TTP_XOR_MULT_DOSStub_2f3c {
  strings:
    $key_2f3c = { 7b 54 [2] 0f 4c [2] 48 4e [2] 0f 5f [2] 41 53 [2] 4d 59 [2] 5a 52 [2] 41 1c [2] 7c }

  condition:
    any of them
}