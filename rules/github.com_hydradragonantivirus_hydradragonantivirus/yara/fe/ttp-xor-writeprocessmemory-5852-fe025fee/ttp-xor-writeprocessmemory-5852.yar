rule TTP_XOR_WriteProcessMemory_5852 {
  strings:
    $key_5852 = { 0f 20 [2] 3d 02 [2] 3b 37 [2] 15 37 [2] 2a 2b }

  condition:
    any of them
}