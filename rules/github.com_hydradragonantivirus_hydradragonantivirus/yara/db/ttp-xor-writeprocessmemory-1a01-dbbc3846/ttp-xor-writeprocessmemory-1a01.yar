rule TTP_XOR_WriteProcessMemory_1a01 {
  strings:
    $key_1a01 = { 4d 73 [2] 7f 51 [2] 79 64 [2] 57 64 [2] 68 78 }

  condition:
    any of them
}