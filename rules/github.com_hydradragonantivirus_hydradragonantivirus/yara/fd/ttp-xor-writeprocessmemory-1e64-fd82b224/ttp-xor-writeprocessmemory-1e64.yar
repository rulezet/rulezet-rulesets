rule TTP_XOR_WriteProcessMemory_1e64 {
  strings:
    $key_1e64 = { 49 16 [2] 7b 34 [2] 7d 01 [2] 53 01 [2] 6c 1d }

  condition:
    any of them
}