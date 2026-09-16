rule TTP_XOR_MULT_DOSStub_2f8a {
  strings:
    $key_2f8a = { 7b e2 [2] 0f fa [2] 48 f8 [2] 0f e9 [2] 41 e5 [2] 4d ef [2] 5a e4 [2] 41 aa [2] 7c }

  condition:
    any of them
}