rule TTP_XOR_WriteProcessMemory_0165 {
  strings:
    $key_0165 = { 56 17 [2] 64 35 [2] 62 00 [2] 4c 00 [2] 73 1c }

  condition:
    any of them
}