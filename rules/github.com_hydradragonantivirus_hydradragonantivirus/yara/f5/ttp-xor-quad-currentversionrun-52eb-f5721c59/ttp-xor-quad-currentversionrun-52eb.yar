rule TTP_XOR_QUAD_CurrentVersionRun_52eb {
  strings:
    $key_52eb = { 01 84 [2] 25 8a [2] 0e a6 [2] 20 84 [2] 34 9f [2] 3b 85 [2] 25 98 [2] 27 99 [2] 3c 9f [2] 20 98 [2] 3c b7 }

  condition:
    any of them
}