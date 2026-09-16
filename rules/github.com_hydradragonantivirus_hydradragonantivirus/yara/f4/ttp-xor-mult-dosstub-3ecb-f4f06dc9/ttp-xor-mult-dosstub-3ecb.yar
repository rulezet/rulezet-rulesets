rule TTP_XOR_MULT_DOSStub_3ecb {
  strings:
    $key_3ecb = { 6a a3 [2] 1e bb [2] 59 b9 [2] 1e a8 [2] 50 a4 [2] 5c ae [2] 4b a5 [2] 50 eb [2] 6d }

  condition:
    any of them
}