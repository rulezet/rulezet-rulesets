rule TTP_XOR_WriteProcessMemory_0964 {
  strings:
    $key_0964 = { 5e 16 [2] 6c 34 [2] 6a 01 [2] 44 01 [2] 7b 1d }

  condition:
    any of them
}