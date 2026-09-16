rule TTP_XOR_MULT_DOSStub_993f {
  strings:
    $key_993f = { cd 57 [2] b9 4f [2] fe 4d [2] b9 5c [2] f7 50 [2] fb 5a [2] ec 51 [2] f7 1f [2] ca }

  condition:
    any of them
}