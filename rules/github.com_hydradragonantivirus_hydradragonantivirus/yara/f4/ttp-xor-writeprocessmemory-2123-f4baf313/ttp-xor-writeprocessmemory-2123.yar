rule TTP_XOR_WriteProcessMemory_2123 {
  strings:
    $key_2123 = { 76 51 [2] 44 73 [2] 42 46 [2] 6c 46 [2] 53 5a }

  condition:
    any of them
}