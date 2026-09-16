rule TTP_XOR_WriteProcessMemory_6a61 {
  strings:
    $key_6a61 = { 3d 13 [2] 0f 31 [2] 09 04 [2] 27 04 [2] 18 18 }

  condition:
    any of them
}