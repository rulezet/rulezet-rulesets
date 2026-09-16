rule TTP_XOR_MULT_DOSStub_995c {
  strings:
    $key_995c = { cd 34 [2] b9 2c [2] fe 2e [2] b9 3f [2] f7 33 [2] fb 39 [2] ec 32 [2] f7 7c [2] ca }

  condition:
    any of them
}