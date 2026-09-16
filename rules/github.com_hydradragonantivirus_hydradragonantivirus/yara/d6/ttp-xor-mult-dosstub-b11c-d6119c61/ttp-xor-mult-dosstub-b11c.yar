rule TTP_XOR_MULT_DOSStub_b11c {
  strings:
    $key_b11c = { e5 74 [2] 91 6c [2] d6 6e [2] 91 7f [2] df 73 [2] d3 79 [2] c4 72 [2] df 3c [2] e2 }

  condition:
    any of them
}