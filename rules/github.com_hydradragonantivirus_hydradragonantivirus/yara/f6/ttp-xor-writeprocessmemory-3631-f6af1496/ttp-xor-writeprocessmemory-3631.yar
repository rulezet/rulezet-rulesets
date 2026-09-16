rule TTP_XOR_WriteProcessMemory_3631 {
  strings:
    $key_3631 = { 61 43 [2] 53 61 [2] 55 54 [2] 7b 54 [2] 44 48 }

  condition:
    any of them
}