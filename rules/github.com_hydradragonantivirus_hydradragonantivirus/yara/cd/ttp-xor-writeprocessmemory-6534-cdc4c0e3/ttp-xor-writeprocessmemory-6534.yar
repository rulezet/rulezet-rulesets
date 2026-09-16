rule TTP_XOR_WriteProcessMemory_6534 {
  strings:
    $key_6534 = { 32 46 [2] 00 64 [2] 06 51 [2] 28 51 [2] 17 4d }

  condition:
    any of them
}