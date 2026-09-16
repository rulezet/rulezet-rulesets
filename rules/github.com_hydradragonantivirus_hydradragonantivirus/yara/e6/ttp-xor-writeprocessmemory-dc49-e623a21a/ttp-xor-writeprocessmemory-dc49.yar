rule TTP_XOR_WriteProcessMemory_dc49 {
  strings:
    $key_dc49 = { 8b 3b [2] b9 19 [2] bf 2c [2] 91 2c [2] ae 30 }

  condition:
    any of them
}