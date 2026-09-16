rule TTP_XOR_MULT_DOSStub_3ddc {
  strings:
    $key_3ddc = { 69 b4 [2] 1d ac [2] 5a ae [2] 1d bf [2] 53 b3 [2] 5f b9 [2] 48 b2 [2] 53 fc [2] 6e }

  condition:
    any of them
}