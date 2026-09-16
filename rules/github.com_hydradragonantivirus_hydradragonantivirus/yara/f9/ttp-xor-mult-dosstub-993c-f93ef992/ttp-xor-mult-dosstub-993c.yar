rule TTP_XOR_MULT_DOSStub_993c {
  strings:
    $key_993c = { cd 54 [2] b9 4c [2] fe 4e [2] b9 5f [2] f7 53 [2] fb 59 [2] ec 52 [2] f7 1c [2] ca }

  condition:
    any of them
}