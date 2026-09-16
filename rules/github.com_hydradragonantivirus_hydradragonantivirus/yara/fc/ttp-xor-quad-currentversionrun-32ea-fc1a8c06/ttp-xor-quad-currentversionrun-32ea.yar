rule TTP_XOR_QUAD_CurrentVersionRun_32ea {
  strings:
    $key_32ea = { 61 85 [2] 45 8b [2] 6e a7 [2] 40 85 [2] 54 9e [2] 5b 84 [2] 45 99 [2] 47 98 [2] 5c 9e [2] 40 99 [2] 5c b6 }

  condition:
    any of them
}