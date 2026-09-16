rule TTP_XOR_WriteProcessMemory_2d10 {
  strings:
    $key_2d10 = { 7a 62 [2] 48 40 [2] 4e 75 [2] 60 75 [2] 5f 69 }

  condition:
    any of them
}