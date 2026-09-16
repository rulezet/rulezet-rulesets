rule TTP_XOR_MULT_DOSStub_e33c {
  strings:
    $key_e33c = { b7 54 [2] c3 4c [2] 84 4e [2] c3 5f [2] 8d 53 [2] 81 59 [2] 96 52 [2] 8d 1c [2] b0 }

  condition:
    any of them
}