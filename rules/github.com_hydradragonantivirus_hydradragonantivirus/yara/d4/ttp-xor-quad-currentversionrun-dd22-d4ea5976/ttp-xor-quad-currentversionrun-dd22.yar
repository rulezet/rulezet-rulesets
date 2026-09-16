rule TTP_XOR_QUAD_CurrentVersionRun_dd22 {
  strings:
    $key_dd22 = { 8e 4d [2] aa 43 [2] 81 6f [2] af 4d [2] bb 56 [2] b4 4c [2] aa 51 [2] a8 50 [2] b3 56 [2] af 51 [2] b3 7e }

  condition:
    any of them
}