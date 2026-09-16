rule TTP_XOR_MULT_DOSStub_0eac {
  strings:
    $key_0eac = { 5a c4 [2] 2e dc [2] 69 de [2] 2e cf [2] 60 c3 [2] 6c c9 [2] 7b c2 [2] 60 8c [2] 5d }

  condition:
    any of them
}