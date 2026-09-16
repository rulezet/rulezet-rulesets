rule TTP_XOR_WriteProcessMemory_6a23 {
  strings:
    $key_6a23 = { 3d 51 [2] 0f 73 [2] 09 46 [2] 27 46 [2] 18 5a }

  condition:
    any of them
}