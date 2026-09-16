rule TTP_XOR_WriteProcessMemory_ee16 {
  strings:
    $key_ee16 = { b9 64 [2] 8b 46 [2] 8d 73 [2] a3 73 [2] 9c 6f }

  condition:
    any of them
}