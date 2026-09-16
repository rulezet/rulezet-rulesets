rule TTP_XOR_QUAD_CurrentVersionRun_dddb {
  strings:
    $key_dddb = { 8e b4 [2] aa ba [2] 81 96 [2] af b4 [2] bb af [2] b4 b5 [2] aa a8 [2] a8 a9 [2] b3 af [2] af a8 [2] b3 87 }

  condition:
    any of them
}