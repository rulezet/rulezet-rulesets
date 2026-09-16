rule TTP_XOR_MULT_DOSStub_9900 {
  strings:
    $key_9900 = { cd 68 [2] b9 70 [2] fe 72 [2] b9 63 [2] f7 6f [2] fb 65 [2] ec 6e [2] f7 20 [2] ca }

  condition:
    any of them
}