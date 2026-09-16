rule TTP_XOR_MULT_DOSStub_824c {
  strings:
    $key_824c = { d6 24 [2] a2 3c [2] e5 3e [2] a2 2f [2] ec 23 [2] e0 29 [2] f7 22 [2] ec 6c [2] d1 }

  condition:
    any of them
}