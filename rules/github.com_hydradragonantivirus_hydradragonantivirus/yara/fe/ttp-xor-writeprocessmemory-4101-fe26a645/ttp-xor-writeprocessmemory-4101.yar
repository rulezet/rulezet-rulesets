rule TTP_XOR_WriteProcessMemory_4101 {
  strings:
    $key_4101 = { 16 73 [2] 24 51 [2] 22 64 [2] 0c 64 [2] 33 78 }

  condition:
    any of them
}