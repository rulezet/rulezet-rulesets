rule TTP_XOR_WriteProcessMemory_ee62 {
  strings:
    $key_ee62 = { b9 10 [2] 8b 32 [2] 8d 07 [2] a3 07 [2] 9c 1b }

  condition:
    any of them
}