rule TTP_XOR_MULT_DOSStub_2fc1 {
  strings:
    $key_2fc1 = { 7b a9 [2] 0f b1 [2] 48 b3 [2] 0f a2 [2] 41 ae [2] 4d a4 [2] 5a af [2] 41 e1 [2] 7c }

  condition:
    any of them
}