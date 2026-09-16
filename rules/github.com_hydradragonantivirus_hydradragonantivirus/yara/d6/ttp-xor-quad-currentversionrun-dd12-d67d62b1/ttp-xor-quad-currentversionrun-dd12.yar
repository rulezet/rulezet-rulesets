rule TTP_XOR_QUAD_CurrentVersionRun_dd12 {
  strings:
    $key_dd12 = { 8e 7d [2] aa 73 [2] 81 5f [2] af 7d [2] bb 66 [2] b4 7c [2] aa 61 [2] a8 60 [2] b3 66 [2] af 61 [2] b3 4e }

  condition:
    any of them
}