rule TTP_XOR_MULT_DOSStub_f603 {
  strings:
    $key_f603 = { a2 6b [2] d6 73 [2] 91 71 [2] d6 60 [2] 98 6c [2] 94 66 [2] 83 6d [2] 98 23 [2] a5 }

  condition:
    any of them
}