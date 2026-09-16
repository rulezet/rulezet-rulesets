rule TTP_XOR_WriteProcessMemory_ee64 {
  strings:
    $key_ee64 = { b9 16 [2] 8b 34 [2] 8d 01 [2] a3 01 [2] 9c 1d }

  condition:
    any of them
}