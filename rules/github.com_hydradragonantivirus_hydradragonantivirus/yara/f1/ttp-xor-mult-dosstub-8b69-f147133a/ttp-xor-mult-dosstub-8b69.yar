rule TTP_XOR_MULT_DOSStub_8b69 {
  strings:
    $key_8b69 = { df 01 [2] ab 19 [2] ec 1b [2] ab 0a [2] e5 06 [2] e9 0c [2] fe 07 [2] e5 49 [2] d8 }

  condition:
    any of them
}