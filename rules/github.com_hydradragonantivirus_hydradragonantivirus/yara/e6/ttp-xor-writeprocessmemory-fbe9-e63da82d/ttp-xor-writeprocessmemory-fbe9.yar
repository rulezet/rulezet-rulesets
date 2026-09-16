rule TTP_XOR_WriteProcessMemory_fbe9 {
  strings:
    $key_fbe9 = { ac 9b [2] 9e b9 [2] 98 8c [2] b6 8c [2] 89 90 }

  condition:
    any of them
}