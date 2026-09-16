rule TTP_XOR_WriteProcessMemory_62f7 {
  strings:
    $key_62f7 = { 35 85 [2] 07 a7 [2] 01 92 [2] 2f 92 [2] 10 8e }

  condition:
    any of them
}