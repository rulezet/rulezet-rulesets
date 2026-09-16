rule TTP_XOR_MULT_DOSStub_8e01 {
  strings:
    $key_8e01 = { da 69 [2] ae 71 [2] e9 73 [2] ae 62 [2] e0 6e [2] ec 64 [2] fb 6f [2] e0 21 [2] dd }

  condition:
    any of them
}