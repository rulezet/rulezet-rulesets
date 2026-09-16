rule TTP_XOR_MULT_DOSStub_6f9c {
  strings:
    $key_6f9c = { 3b f4 [2] 4f ec [2] 08 ee [2] 4f ff [2] 01 f3 [2] 0d f9 [2] 1a f2 [2] 01 bc [2] 3c }

  condition:
    any of them
}