rule TTP_XOR_MULT_DOSStub_999c {
  strings:
    $key_999c = { cd f4 [2] b9 ec [2] fe ee [2] b9 ff [2] f7 f3 [2] fb f9 [2] ec f2 [2] f7 bc [2] ca }

  condition:
    any of them
}