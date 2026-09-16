rule TTP_XOR_WriteProcessMemory_0135 {
  strings:
    $key_0135 = { 56 47 [2] 64 65 [2] 62 50 [2] 4c 50 [2] 73 4c }

  condition:
    any of them
}