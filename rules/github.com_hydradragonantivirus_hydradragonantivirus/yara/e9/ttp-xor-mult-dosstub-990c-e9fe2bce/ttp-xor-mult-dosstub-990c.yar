rule TTP_XOR_MULT_DOSStub_990c {
  strings:
    $key_990c = { cd 64 [2] b9 7c [2] fe 7e [2] b9 6f [2] f7 63 [2] fb 69 [2] ec 62 [2] f7 2c [2] ca }

  condition:
    any of them
}