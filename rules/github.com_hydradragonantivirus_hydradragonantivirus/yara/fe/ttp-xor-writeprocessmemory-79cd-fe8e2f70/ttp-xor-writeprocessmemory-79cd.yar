rule TTP_XOR_WriteProcessMemory_79cd {
  strings:
    $key_79cd = { 2e bf [2] 1c 9d [2] 1a a8 [2] 34 a8 [2] 0b b4 }

  condition:
    any of them
}