rule TTP_XOR_WriteProcessMemory_39e0 {
  strings:
    $key_39e0 = { 6e 92 [2] 5c b0 [2] 5a 85 [2] 74 85 [2] 4b 99 }

  condition:
    any of them
}