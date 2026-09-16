rule TTP_XOR_QUAD_CurrentVersionRun_62eb {
  strings:
    $key_62eb = { 31 84 [2] 15 8a [2] 3e a6 [2] 10 84 [2] 04 9f [2] 0b 85 [2] 15 98 [2] 17 99 [2] 0c 9f [2] 10 98 [2] 0c b7 }

  condition:
    any of them
}