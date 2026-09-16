rule TTP_XOR_WriteProcessMemory_0660 {
  strings:
    $key_0660 = { 51 12 [2] 63 30 [2] 65 05 [2] 4b 05 [2] 74 19 }

  condition:
    any of them
}