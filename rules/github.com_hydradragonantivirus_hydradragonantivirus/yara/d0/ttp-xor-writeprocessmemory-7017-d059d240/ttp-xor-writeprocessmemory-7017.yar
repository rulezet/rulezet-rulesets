rule TTP_XOR_WriteProcessMemory_7017 {
  strings:
    $key_7017 = { 27 65 [2] 15 47 [2] 13 72 [2] 3d 72 [2] 02 6e }

  condition:
    any of them
}