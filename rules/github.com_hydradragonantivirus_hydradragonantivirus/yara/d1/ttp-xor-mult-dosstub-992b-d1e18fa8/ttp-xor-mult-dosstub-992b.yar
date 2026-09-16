rule TTP_XOR_MULT_DOSStub_992b {
  strings:
    $key_992b = { cd 43 [2] b9 5b [2] fe 59 [2] b9 48 [2] f7 44 [2] fb 4e [2] ec 45 [2] f7 0b [2] ca }

  condition:
    any of them
}