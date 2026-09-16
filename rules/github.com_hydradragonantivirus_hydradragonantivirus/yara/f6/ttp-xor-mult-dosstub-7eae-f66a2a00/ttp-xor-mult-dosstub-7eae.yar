rule TTP_XOR_MULT_DOSStub_7eae {
  strings:
    $key_7eae = { 2a c6 [2] 5e de [2] 19 dc [2] 5e cd [2] 10 c1 [2] 1c cb [2] 0b c0 [2] 10 8e [2] 2d }

  condition:
    any of them
}