rule TTP_XOR_WriteProcessMemory_5a15 {
  strings:
    $key_5a15 = { 0d 67 [2] 3f 45 [2] 39 70 [2] 17 70 [2] 28 6c }

  condition:
    any of them
}