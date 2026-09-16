rule TTP_XOR_WriteProcessMemory_0f34 {
  strings:
    $key_0f34 = { 58 46 [2] 6a 64 [2] 6c 51 [2] 42 51 [2] 7d 4d }

  condition:
    any of them
}