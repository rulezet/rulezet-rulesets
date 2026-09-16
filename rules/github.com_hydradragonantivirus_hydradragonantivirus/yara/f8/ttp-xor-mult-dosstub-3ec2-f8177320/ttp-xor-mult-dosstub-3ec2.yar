rule TTP_XOR_MULT_DOSStub_3ec2 {
  strings:
    $key_3ec2 = { 6a aa [2] 1e b2 [2] 59 b0 [2] 1e a1 [2] 50 ad [2] 5c a7 [2] 4b ac [2] 50 e2 [2] 6d }

  condition:
    any of them
}