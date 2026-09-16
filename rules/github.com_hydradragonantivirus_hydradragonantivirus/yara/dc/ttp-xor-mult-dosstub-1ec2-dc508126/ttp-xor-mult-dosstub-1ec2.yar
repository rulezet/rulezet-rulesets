rule TTP_XOR_MULT_DOSStub_1ec2 {
  strings:
    $key_1ec2 = { 4a aa [2] 3e b2 [2] 79 b0 [2] 3e a1 [2] 70 ad [2] 7c a7 [2] 6b ac [2] 70 e2 [2] 4d }

  condition:
    any of them
}