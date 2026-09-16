rule TTP_XOR_QUAD_CurrentVersionRun_e2c5 {
  strings:
    $key_e2c5 = { b1 aa [2] 95 a4 [2] be 88 [2] 90 aa [2] 84 b1 [2] 8b ab [2] 95 b6 [2] 97 b7 [2] 8c b1 [2] 90 b6 [2] 8c 99 }

  condition:
    any of them
}