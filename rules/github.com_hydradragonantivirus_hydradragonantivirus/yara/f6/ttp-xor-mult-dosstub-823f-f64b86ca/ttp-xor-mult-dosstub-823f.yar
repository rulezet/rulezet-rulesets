rule TTP_XOR_MULT_DOSStub_823f {
  strings:
    $key_823f = { d6 57 [2] a2 4f [2] e5 4d [2] a2 5c [2] ec 50 [2] e0 5a [2] f7 51 [2] ec 1f [2] d1 }

  condition:
    any of them
}