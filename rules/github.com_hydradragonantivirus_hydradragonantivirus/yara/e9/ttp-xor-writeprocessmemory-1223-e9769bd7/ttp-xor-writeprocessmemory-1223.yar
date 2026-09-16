rule TTP_XOR_WriteProcessMemory_1223 {
  strings:
    $key_1223 = { 45 51 [2] 77 73 [2] 71 46 [2] 5f 46 [2] 60 5a }

  condition:
    any of them
}