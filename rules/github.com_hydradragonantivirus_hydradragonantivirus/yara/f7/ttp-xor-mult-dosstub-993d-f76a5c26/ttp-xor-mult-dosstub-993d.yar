rule TTP_XOR_MULT_DOSStub_993d {
  strings:
    $key_993d = { cd 55 [2] b9 4d [2] fe 4f [2] b9 5e [2] f7 52 [2] fb 58 [2] ec 53 [2] f7 1d [2] ca }

  condition:
    any of them
}