rule TTP_XOR_WriteProcessMemory_ee21 {
  strings:
    $key_ee21 = { b9 53 [2] 8b 71 [2] 8d 44 [2] a3 44 [2] 9c 58 }

  condition:
    any of them
}