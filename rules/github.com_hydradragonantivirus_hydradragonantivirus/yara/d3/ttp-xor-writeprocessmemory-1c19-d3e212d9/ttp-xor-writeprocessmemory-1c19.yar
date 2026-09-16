rule TTP_XOR_WriteProcessMemory_1c19 {
  strings:
    $key_1c19 = { 4b 6b [2] 79 49 [2] 7f 7c [2] 51 7c [2] 6e 60 }

  condition:
    any of them
}