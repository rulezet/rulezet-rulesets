rule TTP_XOR_QUAD_CurrentVersionRun_62ea {
  strings:
    $key_62ea = { 31 85 [2] 15 8b [2] 3e a7 [2] 10 85 [2] 04 9e [2] 0b 84 [2] 15 99 [2] 17 98 [2] 0c 9e [2] 10 99 [2] 0c b6 }

  condition:
    any of them
}