rule TTP_XOR_MULT_DOSStub_fbcb {
  strings:
    $key_fbcb = { af a3 [2] db bb [2] 9c b9 [2] db a8 [2] 95 a4 [2] 99 ae [2] 8e a5 [2] 95 eb [2] a8 }

  condition:
    any of them
}