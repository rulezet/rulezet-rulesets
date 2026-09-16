rule TTP_XOR_WriteProcessMemory_7cc2 {
  strings:
    $key_7cc2 = { 2b b0 [2] 19 92 [2] 1f a7 [2] 31 a7 [2] 0e bb }

  condition:
    any of them
}