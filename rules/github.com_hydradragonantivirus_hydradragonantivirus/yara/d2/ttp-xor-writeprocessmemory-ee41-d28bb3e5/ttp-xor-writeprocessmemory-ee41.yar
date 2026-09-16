rule TTP_XOR_WriteProcessMemory_ee41 {
  strings:
    $key_ee41 = { b9 33 [2] 8b 11 [2] 8d 24 [2] a3 24 [2] 9c 38 }

  condition:
    any of them
}