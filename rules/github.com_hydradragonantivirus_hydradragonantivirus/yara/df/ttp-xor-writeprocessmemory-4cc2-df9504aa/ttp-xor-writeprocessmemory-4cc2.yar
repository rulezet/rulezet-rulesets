rule TTP_XOR_WriteProcessMemory_4cc2 {
  strings:
    $key_4cc2 = { 1b b0 [2] 29 92 [2] 2f a7 [2] 01 a7 [2] 3e bb }

  condition:
    any of them
}