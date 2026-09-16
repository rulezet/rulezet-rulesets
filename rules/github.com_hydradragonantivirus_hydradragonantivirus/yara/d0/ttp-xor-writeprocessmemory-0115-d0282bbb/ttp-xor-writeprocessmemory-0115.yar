rule TTP_XOR_WriteProcessMemory_0115 {
  strings:
    $key_0115 = { 56 67 [2] 64 45 [2] 62 70 [2] 4c 70 [2] 73 6c }

  condition:
    any of them
}