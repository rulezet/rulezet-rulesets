rule TTP_XOR_WriteProcessMemory_4f34 {
  strings:
    $key_4f34 = { 18 46 [2] 2a 64 [2] 2c 51 [2] 02 51 [2] 3d 4d }

  condition:
    any of them
}