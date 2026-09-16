rule TTP_XOR_MULT_DOSStub_1f37 {
  strings:
    $key_1f37 = { 4b 5f [2] 3f 47 [2] 78 45 [2] 3f 54 [2] 71 58 [2] 7d 52 [2] 6a 59 [2] 71 17 [2] 4c }

  condition:
    any of them
}