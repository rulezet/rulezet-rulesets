rule TTP_XOR_MULT_DOSStub_b103 {
  strings:
    $key_b103 = { e5 6b [2] 91 73 [2] d6 71 [2] 91 60 [2] df 6c [2] d3 66 [2] c4 6d [2] df 23 [2] e2 }

  condition:
    any of them
}