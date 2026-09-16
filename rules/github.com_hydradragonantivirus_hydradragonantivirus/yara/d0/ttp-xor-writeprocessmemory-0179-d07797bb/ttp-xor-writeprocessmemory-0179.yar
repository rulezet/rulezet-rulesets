rule TTP_XOR_WriteProcessMemory_0179 {
  strings:
    $key_0179 = { 56 0b [2] 64 29 [2] 62 1c [2] 4c 1c [2] 73 00 }

  condition:
    any of them
}