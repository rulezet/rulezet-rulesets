rule TTP_XOR_WriteProcessMemory_1339 {
  strings:
    $key_1339 = { 44 4b [2] 76 69 [2] 70 5c [2] 5e 5c [2] 61 40 }

  condition:
    any of them
}