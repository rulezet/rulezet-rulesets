rule TTP_XOR_WriteProcessMemory_6dc6 {
  strings:
    $key_6dc6 = { 3a b4 [2] 08 96 [2] 0e a3 [2] 20 a3 [2] 1f bf }

  condition:
    any of them
}