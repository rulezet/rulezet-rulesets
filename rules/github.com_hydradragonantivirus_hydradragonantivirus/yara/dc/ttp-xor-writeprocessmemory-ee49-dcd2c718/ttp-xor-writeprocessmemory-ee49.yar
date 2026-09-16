rule TTP_XOR_WriteProcessMemory_ee49 {
  strings:
    $key_ee49 = { b9 3b [2] 8b 19 [2] 8d 2c [2] a3 2c [2] 9c 30 }

  condition:
    any of them
}