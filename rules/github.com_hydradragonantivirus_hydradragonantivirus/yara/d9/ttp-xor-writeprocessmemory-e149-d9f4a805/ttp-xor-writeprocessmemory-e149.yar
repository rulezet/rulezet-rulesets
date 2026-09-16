rule TTP_XOR_WriteProcessMemory_e149 {
  strings:
    $key_e149 = { b6 3b [2] 84 19 [2] 82 2c [2] ac 2c [2] 93 30 }

  condition:
    any of them
}