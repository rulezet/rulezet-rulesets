rule TTP_XOR_MULT_DOSStub_9947 {
  strings:
    $key_9947 = { cd 2f [2] b9 37 [2] fe 35 [2] b9 24 [2] f7 28 [2] fb 22 [2] ec 29 [2] f7 67 [2] ca }

  condition:
    any of them
}