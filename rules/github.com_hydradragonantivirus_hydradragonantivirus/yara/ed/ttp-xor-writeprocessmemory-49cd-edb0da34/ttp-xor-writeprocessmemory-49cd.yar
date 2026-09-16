rule TTP_XOR_WriteProcessMemory_49cd {
  strings:
    $key_49cd = { 1e bf [2] 2c 9d [2] 2a a8 [2] 04 a8 [2] 3b b4 }

  condition:
    any of them
}