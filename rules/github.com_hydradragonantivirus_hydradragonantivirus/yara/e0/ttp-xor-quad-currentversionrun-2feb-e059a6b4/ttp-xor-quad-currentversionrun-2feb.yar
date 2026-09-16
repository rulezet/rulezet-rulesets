rule TTP_XOR_QUAD_CurrentVersionRun_2feb {
  strings:
    $key_2feb = { 7c 84 [2] 58 8a [2] 73 a6 [2] 5d 84 [2] 49 9f [2] 46 85 [2] 58 98 [2] 5a 99 [2] 41 9f [2] 5d 98 [2] 41 b7 }

  condition:
    any of them
}