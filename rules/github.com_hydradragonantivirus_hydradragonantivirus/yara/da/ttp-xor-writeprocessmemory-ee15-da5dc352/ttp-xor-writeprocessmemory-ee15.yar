rule TTP_XOR_WriteProcessMemory_ee15 {
  strings:
    $key_ee15 = { b9 67 [2] 8b 45 [2] 8d 70 [2] a3 70 [2] 9c 6c }

  condition:
    any of them
}