rule TTP_XOR_WriteProcessMemory_4952 {
  strings:
    $key_4952 = { 1e 20 [2] 2c 02 [2] 2a 37 [2] 04 37 [2] 3b 2b }

  condition:
    any of them
}