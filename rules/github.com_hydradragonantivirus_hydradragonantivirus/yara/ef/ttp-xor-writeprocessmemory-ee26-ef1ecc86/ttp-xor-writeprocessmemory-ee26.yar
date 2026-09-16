rule TTP_XOR_WriteProcessMemory_ee26 {
  strings:
    $key_ee26 = { b9 54 [2] 8b 76 [2] 8d 43 [2] a3 43 [2] 9c 5f }

  condition:
    any of them
}