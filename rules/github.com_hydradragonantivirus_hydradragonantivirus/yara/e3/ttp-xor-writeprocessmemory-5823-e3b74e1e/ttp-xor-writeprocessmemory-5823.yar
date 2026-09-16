rule TTP_XOR_WriteProcessMemory_5823 {
  strings:
    $key_5823 = { 0f 51 [2] 3d 73 [2] 3b 46 [2] 15 46 [2] 2a 5a }

  condition:
    any of them
}