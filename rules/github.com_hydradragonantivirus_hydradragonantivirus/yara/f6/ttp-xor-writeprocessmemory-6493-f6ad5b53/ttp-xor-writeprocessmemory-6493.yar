rule TTP_XOR_WriteProcessMemory_6493 {
  strings:
    $key_6493 = { 33 e1 [2] 01 c3 [2] 07 f6 [2] 29 f6 [2] 16 ea }

  condition:
    any of them
}