rule TTP_XOR_WriteProcessMemory_c949 {
  strings:
    $key_c949 = { 9e 3b [2] ac 19 [2] aa 2c [2] 84 2c [2] bb 30 }

  condition:
    any of them
}