rule TTP_XOR_QUAD_CurrentVersionRun_52ea {
  strings:
    $key_52ea = { 01 85 [2] 25 8b [2] 0e a7 [2] 20 85 [2] 34 9e [2] 3b 84 [2] 25 99 [2] 27 98 [2] 3c 9e [2] 20 99 [2] 3c b6 }

  condition:
    any of them
}