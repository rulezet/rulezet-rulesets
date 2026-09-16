rule TTP_XOR_WriteProcessMemory_2a01 {
  strings:
    $key_2a01 = { 7d 73 [2] 4f 51 [2] 49 64 [2] 67 64 [2] 58 78 }

  condition:
    any of them
}