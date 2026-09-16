rule TTP_XOR_MULT_DOSStub_2f13 {
  strings:
    $key_2f13 = { 7b 7b [2] 0f 63 [2] 48 61 [2] 0f 70 [2] 41 7c [2] 4d 76 [2] 5a 7d [2] 41 33 [2] 7c }

  condition:
    any of them
}