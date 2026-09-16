rule TTP_XOR_MULT_DOSStub_d925 {
  strings:
    $key_d925 = { 8d 4d [2] f9 55 [2] be 57 [2] f9 46 [2] b7 4a [2] bb 40 [2] ac 4b [2] b7 05 [2] 8a }

  condition:
    any of them
}