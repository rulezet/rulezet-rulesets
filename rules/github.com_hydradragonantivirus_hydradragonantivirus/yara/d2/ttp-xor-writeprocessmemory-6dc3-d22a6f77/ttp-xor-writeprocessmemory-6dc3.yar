rule TTP_XOR_WriteProcessMemory_6dc3 {
  strings:
    $key_6dc3 = { 3a b1 [2] 08 93 [2] 0e a6 [2] 20 a6 [2] 1f ba }

  condition:
    any of them
}