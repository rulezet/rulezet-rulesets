rule TTP_XOR_MULT_DOSStub_fbcd {
  strings:
    $key_fbcd = { af a5 [2] db bd [2] 9c bf [2] db ae [2] 95 a2 [2] 99 a8 [2] 8e a3 [2] 95 ed [2] a8 }

  condition:
    any of them
}