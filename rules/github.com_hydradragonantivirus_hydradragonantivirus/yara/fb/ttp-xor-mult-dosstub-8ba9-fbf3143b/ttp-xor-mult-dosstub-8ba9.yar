rule TTP_XOR_MULT_DOSStub_8ba9 {
  strings:
    $key_8ba9 = { df c1 [2] ab d9 [2] ec db [2] ab ca [2] e5 c6 [2] e9 cc [2] fe c7 [2] e5 89 [2] d8 }

  condition:
    any of them
}