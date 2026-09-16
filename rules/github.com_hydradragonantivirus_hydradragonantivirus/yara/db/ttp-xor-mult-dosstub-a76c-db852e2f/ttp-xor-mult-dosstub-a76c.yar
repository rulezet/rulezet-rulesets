rule TTP_XOR_MULT_DOSStub_a76c {
  strings:
    $key_a76c = { f3 04 [2] 87 1c [2] c0 1e [2] 87 0f [2] c9 03 [2] c5 09 [2] d2 02 [2] c9 4c [2] f4 }

  condition:
    any of them
}