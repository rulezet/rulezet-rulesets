rule TTP_XOR_MULT_DOSStub_824f {
  strings:
    $key_824f = { d6 27 [2] a2 3f [2] e5 3d [2] a2 2c [2] ec 20 [2] e0 2a [2] f7 21 [2] ec 6f [2] d1 }

  condition:
    any of them
}