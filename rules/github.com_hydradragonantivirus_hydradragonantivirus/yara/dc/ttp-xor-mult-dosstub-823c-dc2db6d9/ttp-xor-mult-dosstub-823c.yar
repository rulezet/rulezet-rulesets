rule TTP_XOR_MULT_DOSStub_823c {
  strings:
    $key_823c = { d6 54 [2] a2 4c [2] e5 4e [2] a2 5f [2] ec 53 [2] e0 59 [2] f7 52 [2] ec 1c [2] d1 }

  condition:
    any of them
}