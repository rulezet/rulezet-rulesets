rule TTP_XOR_MULT_DOSStub_b21c {
  strings:
    $key_b21c = { e6 74 [2] 92 6c [2] d5 6e [2] 92 7f [2] dc 73 [2] d0 79 [2] c7 72 [2] dc 3c [2] e1 }

  condition:
    any of them
}