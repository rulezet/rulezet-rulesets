rule TTP_XOR_WriteProcessMemory_6a77 {
  strings:
    $key_6a77 = { 3d 05 [2] 0f 27 [2] 09 12 [2] 27 12 [2] 18 0e }

  condition:
    any of them
}