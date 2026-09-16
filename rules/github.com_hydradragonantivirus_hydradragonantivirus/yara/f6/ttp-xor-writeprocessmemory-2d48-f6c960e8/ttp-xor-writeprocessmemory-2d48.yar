rule TTP_XOR_WriteProcessMemory_2d48 {
  strings:
    $key_2d48 = { 7a 3a [2] 48 18 [2] 4e 2d [2] 60 2d [2] 5f 31 }

  condition:
    any of them
}