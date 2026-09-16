rule TTP_XOR_WriteProcessMemory_1dc3 {
  strings:
    $key_1dc3 = { 4a b1 [2] 78 93 [2] 7e a6 [2] 50 a6 [2] 6f ba }

  condition:
    any of them
}