rule TTP_XOR_WriteProcessMemory_0f67 {
  strings:
    $key_0f67 = { 58 15 [2] 6a 37 [2] 6c 02 [2] 42 02 [2] 7d 1e }

  condition:
    any of them
}