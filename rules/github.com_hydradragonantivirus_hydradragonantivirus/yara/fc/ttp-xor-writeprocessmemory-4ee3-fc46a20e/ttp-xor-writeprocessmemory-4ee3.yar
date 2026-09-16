rule TTP_XOR_WriteProcessMemory_4ee3 {
  strings:
    $key_4ee3 = { 19 91 [2] 2b b3 [2] 2d 86 [2] 03 86 [2] 3c 9a }

  condition:
    any of them
}