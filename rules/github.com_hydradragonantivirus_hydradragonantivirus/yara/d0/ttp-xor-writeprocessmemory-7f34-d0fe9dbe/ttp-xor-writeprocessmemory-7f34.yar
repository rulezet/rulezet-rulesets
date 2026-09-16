rule TTP_XOR_WriteProcessMemory_7f34 {
  strings:
    $key_7f34 = { 28 46 [2] 1a 64 [2] 1c 51 [2] 32 51 [2] 0d 4d }

  condition:
    any of them
}