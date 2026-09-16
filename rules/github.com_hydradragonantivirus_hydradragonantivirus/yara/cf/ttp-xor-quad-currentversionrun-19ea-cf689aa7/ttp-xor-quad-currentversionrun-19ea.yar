rule TTP_XOR_QUAD_CurrentVersionRun_19ea {
  strings:
    $key_19ea = { 4a 85 [2] 6e 8b [2] 45 a7 [2] 6b 85 [2] 7f 9e [2] 70 84 [2] 6e 99 [2] 6c 98 [2] 77 9e [2] 6b 99 [2] 77 b6 }

  condition:
    any of them
}