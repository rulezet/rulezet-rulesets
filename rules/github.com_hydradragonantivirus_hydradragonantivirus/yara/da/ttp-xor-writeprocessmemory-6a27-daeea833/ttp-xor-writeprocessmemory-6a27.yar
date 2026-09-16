rule TTP_XOR_WriteProcessMemory_6a27 {
  strings:
    $key_6a27 = { 3d 55 [2] 0f 77 [2] 09 42 [2] 27 42 [2] 18 5e }

  condition:
    any of them
}