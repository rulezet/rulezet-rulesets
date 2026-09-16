rule TTP_XOR_MULT_DOSStub_8a91 {
  strings:
    $key_8a91 = { de f9 [2] aa e1 [2] ed e3 [2] aa f2 [2] e4 fe [2] e8 f4 [2] ff ff [2] e4 b1 [2] d9 }

  condition:
    any of them
}