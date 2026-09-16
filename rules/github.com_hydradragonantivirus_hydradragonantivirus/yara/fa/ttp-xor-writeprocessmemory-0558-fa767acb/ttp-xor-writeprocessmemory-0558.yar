rule TTP_XOR_WriteProcessMemory_0558 {
  strings:
    $key_0558 = { 52 2a [2] 60 08 [2] 66 3d [2] 48 3d [2] 77 21 }

  condition:
    any of them
}