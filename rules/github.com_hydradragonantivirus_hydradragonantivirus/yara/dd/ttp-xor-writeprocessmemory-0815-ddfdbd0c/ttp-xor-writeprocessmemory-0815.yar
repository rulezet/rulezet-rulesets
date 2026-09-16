rule TTP_XOR_WriteProcessMemory_0815 {
  strings:
    $key_0815 = { 5f 67 [2] 6d 45 [2] 6b 70 [2] 45 70 [2] 7a 6c }

  condition:
    any of them
}