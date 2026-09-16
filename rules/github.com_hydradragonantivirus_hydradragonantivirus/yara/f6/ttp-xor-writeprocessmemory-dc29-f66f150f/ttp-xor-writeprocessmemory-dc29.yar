rule TTP_XOR_WriteProcessMemory_dc29 {
  strings:
    $key_dc29 = { 8b 5b [2] b9 79 [2] bf 4c [2] 91 4c [2] ae 50 }

  condition:
    any of them
}