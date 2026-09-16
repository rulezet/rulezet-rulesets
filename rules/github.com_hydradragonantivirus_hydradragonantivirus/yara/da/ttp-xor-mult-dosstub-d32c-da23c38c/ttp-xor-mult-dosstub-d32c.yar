rule TTP_XOR_MULT_DOSStub_d32c {
  strings:
    $key_d32c = { 87 44 [2] f3 5c [2] b4 5e [2] f3 4f [2] bd 43 [2] b1 49 [2] a6 42 [2] bd 0c [2] 80 }

  condition:
    any of them
}