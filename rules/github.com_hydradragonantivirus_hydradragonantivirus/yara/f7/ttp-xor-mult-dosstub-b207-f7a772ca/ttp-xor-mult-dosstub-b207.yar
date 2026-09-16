rule TTP_XOR_MULT_DOSStub_b207 {
  strings:
    $key_b207 = { e6 6f [2] 92 77 [2] d5 75 [2] 92 64 [2] dc 68 [2] d0 62 [2] c7 69 [2] dc 27 [2] e1 }

  condition:
    any of them
}