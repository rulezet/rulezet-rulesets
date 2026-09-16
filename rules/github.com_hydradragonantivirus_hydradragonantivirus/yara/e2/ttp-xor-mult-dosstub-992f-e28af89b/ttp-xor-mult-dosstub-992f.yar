rule TTP_XOR_MULT_DOSStub_992f {
  strings:
    $key_992f = { cd 47 [2] b9 5f [2] fe 5d [2] b9 4c [2] f7 40 [2] fb 4a [2] ec 41 [2] f7 0f [2] ca }

  condition:
    any of them
}