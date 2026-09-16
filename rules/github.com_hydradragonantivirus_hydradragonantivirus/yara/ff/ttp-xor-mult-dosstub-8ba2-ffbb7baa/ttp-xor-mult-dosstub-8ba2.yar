rule TTP_XOR_MULT_DOSStub_8ba2 {
  strings:
    $key_8ba2 = { df ca [2] ab d2 [2] ec d0 [2] ab c1 [2] e5 cd [2] e9 c7 [2] fe cc [2] e5 82 [2] d8 }

  condition:
    any of them
}