rule TTP_XOR_MULT_DOSStub_0ecb {
  strings:
    $key_0ecb = { 5a a3 [2] 2e bb [2] 69 b9 [2] 2e a8 [2] 60 a4 [2] 6c ae [2] 7b a5 [2] 60 eb [2] 5d }

  condition:
    any of them
}