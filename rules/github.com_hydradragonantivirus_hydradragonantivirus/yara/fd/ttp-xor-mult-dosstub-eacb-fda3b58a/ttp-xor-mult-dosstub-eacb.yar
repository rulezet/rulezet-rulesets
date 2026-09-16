rule TTP_XOR_MULT_DOSStub_eacb {
  strings:
    $key_eacb = { be a3 [2] ca bb [2] 8d b9 [2] ca a8 [2] 84 a4 [2] 88 ae [2] 9f a5 [2] 84 eb [2] b9 }

  condition:
    any of them
}