rule TTP_XOR_MULT_DOSStub_bbcc {
  strings:
    $key_bbcc = { ef a4 [2] 9b bc [2] dc be [2] 9b af [2] d5 a3 [2] d9 a9 [2] ce a2 [2] d5 ec [2] e8 }

  condition:
    any of them
}