rule TTP_XOR_MULT_DOSStub_99fd {
  strings:
    $key_99fd = { cd 95 [2] b9 8d [2] fe 8f [2] b9 9e [2] f7 92 [2] fb 98 [2] ec 93 [2] f7 dd [2] ca }

  condition:
    any of them
}