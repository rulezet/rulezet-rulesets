rule TTP_XOR_MULT_DOSStub_997a {
  strings:
    $key_997a = { cd 12 [2] b9 0a [2] fe 08 [2] b9 19 [2] f7 15 [2] fb 1f [2] ec 14 [2] f7 5a [2] ca }

  condition:
    any of them
}