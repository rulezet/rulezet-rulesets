rule TTP_XOR_MULT_DOSStub_2f37 {
  strings:
    $key_2f37 = { 7b 5f [2] 0f 47 [2] 48 45 [2] 0f 54 [2] 41 58 [2] 4d 52 [2] 5a 59 [2] 41 17 [2] 7c }

  condition:
    any of them
}