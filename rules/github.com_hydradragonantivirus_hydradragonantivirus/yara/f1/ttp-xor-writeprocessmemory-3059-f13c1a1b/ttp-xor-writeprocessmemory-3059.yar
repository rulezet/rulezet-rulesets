rule TTP_XOR_WriteProcessMemory_3059 {
  strings:
    $key_3059 = { 67 2b [2] 55 09 [2] 53 3c [2] 7d 3c [2] 42 20 }

  condition:
    any of them
}