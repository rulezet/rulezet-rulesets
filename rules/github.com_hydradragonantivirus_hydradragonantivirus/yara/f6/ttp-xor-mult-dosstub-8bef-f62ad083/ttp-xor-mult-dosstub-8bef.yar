rule TTP_XOR_MULT_DOSStub_8bef {
  strings:
    $key_8bef = { df 87 [2] ab 9f [2] ec 9d [2] ab 8c [2] e5 80 [2] e9 8a [2] fe 81 [2] e5 cf [2] d8 }

  condition:
    any of them
}