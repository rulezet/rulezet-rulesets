rule TTP_XOR_WriteProcessMemory_62f1 {
  strings:
    $key_62f1 = { 35 83 [2] 07 a1 [2] 01 94 [2] 2f 94 [2] 10 88 }

  condition:
    any of them
}