rule TTP_XOR_MULT_DOSStub_0acd {
  strings:
    $key_0acd = { 5e a5 [2] 2a bd [2] 6d bf [2] 2a ae [2] 64 a2 [2] 68 a8 [2] 7f a3 [2] 64 ed [2] 59 }

  condition:
    any of them
}