rule TTP_XOR_WriteProcessMemory_2dc3 {
  strings:
    $key_2dc3 = { 7a b1 [2] 48 93 [2] 4e a6 [2] 60 a6 [2] 5f ba }

  condition:
    any of them
}