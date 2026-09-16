rule TTP_XOR_WriteProcessMemory_1ef5 {
  strings:
    $key_1ef5 = { 49 87 [2] 7b a5 [2] 7d 90 [2] 53 90 [2] 6c 8c }

  condition:
    any of them
}