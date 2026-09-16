rule TTP_XOR_WriteProcessMemory_6ef5 {
  strings:
    $key_6ef5 = { 39 87 [2] 0b a5 [2] 0d 90 [2] 23 90 [2] 1c 8c }

  condition:
    any of them
}