rule TTP_XOR_WriteProcessMemory_4f03 {
  strings:
    $key_4f03 = { 18 71 [2] 2a 53 [2] 2c 66 [2] 02 66 [2] 3d 7a }

  condition:
    any of them
}