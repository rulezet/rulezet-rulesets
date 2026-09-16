rule TTP_XOR_MULT_DOSStub_48df {
  strings:
    $key_48df = { 1c b7 [2] 68 af [2] 2f ad [2] 68 bc [2] 26 b0 [2] 2a ba [2] 3d b1 [2] 26 ff [2] 1b }

  condition:
    any of them
}