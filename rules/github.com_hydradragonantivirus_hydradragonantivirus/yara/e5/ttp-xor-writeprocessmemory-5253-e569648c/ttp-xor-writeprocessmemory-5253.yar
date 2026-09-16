rule TTP_XOR_WriteProcessMemory_5253 {
  strings:
    $key_5253 = { 05 21 [2] 37 03 [2] 31 36 [2] 1f 36 [2] 20 2a }

  condition:
    any of them
}