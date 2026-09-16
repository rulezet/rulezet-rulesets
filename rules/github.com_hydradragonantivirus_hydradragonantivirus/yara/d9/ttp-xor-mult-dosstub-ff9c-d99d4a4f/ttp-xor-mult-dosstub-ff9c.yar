rule TTP_XOR_MULT_DOSStub_ff9c {
  strings:
    $key_ff9c = { ab f4 [2] df ec [2] 98 ee [2] df ff [2] 91 f3 [2] 9d f9 [2] 8a f2 [2] 91 bc [2] ac }

  condition:
    any of them
}