rule TTP_XOR_WriteProcessMemory_39cd {
  strings:
    $key_39cd = { 6e bf [2] 5c 9d [2] 5a a8 [2] 74 a8 [2] 4b b4 }

  condition:
    any of them
}