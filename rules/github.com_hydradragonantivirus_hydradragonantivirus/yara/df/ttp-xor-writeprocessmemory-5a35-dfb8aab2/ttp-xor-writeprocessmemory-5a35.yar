rule TTP_XOR_WriteProcessMemory_5a35 {
  strings:
    $key_5a35 = { 0d 47 [2] 3f 65 [2] 39 50 [2] 17 50 [2] 28 4c }

  condition:
    any of them
}