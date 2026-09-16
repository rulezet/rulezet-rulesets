rule TTP_XOR_QUAD_CurrentVersionRun_2ec2 {
  strings:
    $key_2ec2 = { 7d ad [2] 59 a3 [2] 72 8f [2] 5c ad [2] 48 b6 [2] 47 ac [2] 59 b1 [2] 5b b0 [2] 40 b6 [2] 5c b1 [2] 40 9e }

  condition:
    any of them
}