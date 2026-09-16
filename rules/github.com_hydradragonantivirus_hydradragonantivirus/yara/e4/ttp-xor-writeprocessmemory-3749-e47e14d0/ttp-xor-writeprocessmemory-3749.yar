rule TTP_XOR_WriteProcessMemory_3749 {
  strings:
    $key_3749 = { 60 3b [2] 52 19 [2] 54 2c [2] 7a 2c [2] 45 30 }

  condition:
    any of them
}