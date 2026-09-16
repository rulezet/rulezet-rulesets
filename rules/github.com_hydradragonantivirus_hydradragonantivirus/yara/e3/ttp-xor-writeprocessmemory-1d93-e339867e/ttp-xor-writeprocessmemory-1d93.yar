rule TTP_XOR_WriteProcessMemory_1d93 {
  strings:
    $key_1d93 = { 4a e1 [2] 78 c3 [2] 7e f6 [2] 50 f6 [2] 6f ea }

  condition:
    any of them
}