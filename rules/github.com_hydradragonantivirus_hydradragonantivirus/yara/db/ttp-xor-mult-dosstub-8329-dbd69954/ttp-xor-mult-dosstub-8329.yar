rule TTP_XOR_MULT_DOSStub_8329 {
  strings:
    $key_8329 = { d7 41 [2] a3 59 [2] e4 5b [2] a3 4a [2] ed 46 [2] e1 4c [2] f6 47 [2] ed 09 [2] d0 }

  condition:
    any of them
}