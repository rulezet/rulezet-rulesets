rule TTP_XOR_WriteProcessMemory_0649 {
  strings:
    $key_0649 = { 51 3b [2] 63 19 [2] 65 2c [2] 4b 2c [2] 74 30 }

  condition:
    any of them
}