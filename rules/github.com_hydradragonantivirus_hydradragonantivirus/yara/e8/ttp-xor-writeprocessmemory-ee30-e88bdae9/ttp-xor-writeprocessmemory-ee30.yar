rule TTP_XOR_WriteProcessMemory_ee30 {
  strings:
    $key_ee30 = { b9 42 [2] 8b 60 [2] 8d 55 [2] a3 55 [2] 9c 49 }

  condition:
    any of them
}