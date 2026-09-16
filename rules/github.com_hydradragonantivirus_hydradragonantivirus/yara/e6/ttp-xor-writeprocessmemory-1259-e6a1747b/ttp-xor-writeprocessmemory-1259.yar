rule TTP_XOR_WriteProcessMemory_1259 {
  strings:
    $key_1259 = { 45 2b [2] 77 09 [2] 71 3c [2] 5f 3c [2] 60 20 }

  condition:
    any of them
}