rule TTP_XOR_MULT_DOSStub_992a {
  strings:
    $key_992a = { cd 42 [2] b9 5a [2] fe 58 [2] b9 49 [2] f7 45 [2] fb 4f [2] ec 44 [2] f7 0a [2] ca }

  condition:
    any of them
}