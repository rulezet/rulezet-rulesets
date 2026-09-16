rule TTP_XOR_WriteProcessMemory_ee00 {
  strings:
    $key_ee00 = { b9 72 [2] 8b 50 [2] 8d 65 [2] a3 65 [2] 9c 79 }

  condition:
    any of them
}