rule TTP_XOR_MULT_DOSStub_a0ed {
  strings:
    $key_a0ed = { f4 85 [2] 80 9d [2] c7 9f [2] 80 8e [2] ce 82 [2] c2 88 [2] d5 83 [2] ce cd [2] f3 }

  condition:
    any of them
}