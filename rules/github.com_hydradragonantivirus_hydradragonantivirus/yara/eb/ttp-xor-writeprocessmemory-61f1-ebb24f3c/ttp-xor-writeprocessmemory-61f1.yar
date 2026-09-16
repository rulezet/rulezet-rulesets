rule TTP_XOR_WriteProcessMemory_61f1 {
  strings:
    $key_61f1 = { 36 83 [2] 04 a1 [2] 02 94 [2] 2c 94 [2] 13 88 }

  condition:
    any of them
}