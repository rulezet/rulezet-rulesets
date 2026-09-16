rule TTP_XOR_WriteProcessMemory_4909 {
  strings:
    $key_4909 = { 1e 7b [2] 2c 59 [2] 2a 6c [2] 04 6c [2] 3b 70 }

  condition:
    any of them
}