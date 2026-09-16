rule TTP_XOR_WriteProcessMemory_2ce9 {
  strings:
    $key_2ce9 = { 7b 9b [2] 49 b9 [2] 4f 8c [2] 61 8c [2] 5e 90 }

  condition:
    any of them
}