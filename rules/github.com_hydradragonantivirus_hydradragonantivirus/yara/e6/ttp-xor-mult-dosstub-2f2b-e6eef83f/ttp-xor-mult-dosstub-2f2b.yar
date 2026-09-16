rule TTP_XOR_MULT_DOSStub_2f2b {
  strings:
    $key_2f2b = { 7b 43 [2] 0f 5b [2] 48 59 [2] 0f 48 [2] 41 44 [2] 4d 4e [2] 5a 45 [2] 41 0b [2] 7c }

  condition:
    any of them
}