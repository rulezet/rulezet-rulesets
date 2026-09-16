rule TTP_XOR_MULT_DOSStub_8ba0 {
  strings:
    $key_8ba0 = { df c8 [2] ab d0 [2] ec d2 [2] ab c3 [2] e5 cf [2] e9 c5 [2] fe ce [2] e5 80 [2] d8 }

  condition:
    any of them
}