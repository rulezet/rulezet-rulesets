rule TTP_XOR_WriteProcessMemory_2104 {
  strings:
    $key_2104 = { 76 76 [2] 44 54 [2] 42 61 [2] 6c 61 [2] 53 7d }

  condition:
    any of them
}