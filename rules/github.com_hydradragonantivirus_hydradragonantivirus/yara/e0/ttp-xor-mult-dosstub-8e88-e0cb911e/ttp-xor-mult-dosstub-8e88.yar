rule TTP_XOR_MULT_DOSStub_8e88 {
  strings:
    $key_8e88 = { da e0 [2] ae f8 [2] e9 fa [2] ae eb [2] e0 e7 [2] ec ed [2] fb e6 [2] e0 a8 [2] dd }

  condition:
    any of them
}