rule TTP_XOR_WriteProcessMemory_6a53 {
  strings:
    $key_6a53 = { 3d 21 [2] 0f 03 [2] 09 36 [2] 27 36 [2] 18 2a }

  condition:
    any of them
}