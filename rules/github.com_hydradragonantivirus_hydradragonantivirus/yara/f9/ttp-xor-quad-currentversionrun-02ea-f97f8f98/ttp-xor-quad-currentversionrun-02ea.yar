rule TTP_XOR_QUAD_CurrentVersionRun_02ea {
  strings:
    $key_02ea = { 51 85 [2] 75 8b [2] 5e a7 [2] 70 85 [2] 64 9e [2] 6b 84 [2] 75 99 [2] 77 98 [2] 6c 9e [2] 70 99 [2] 6c b6 }

  condition:
    any of them
}