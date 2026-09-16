rule TTP_XOR_MULT_DOSStub_2f33 {
  strings:
    $key_2f33 = { 7b 5b [2] 0f 43 [2] 48 41 [2] 0f 50 [2] 41 5c [2] 4d 56 [2] 5a 5d [2] 41 13 [2] 7c }

  condition:
    any of them
}