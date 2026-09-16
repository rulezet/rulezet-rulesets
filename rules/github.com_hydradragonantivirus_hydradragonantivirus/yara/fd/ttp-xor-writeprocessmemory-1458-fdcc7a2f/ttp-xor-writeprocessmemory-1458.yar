rule TTP_XOR_WriteProcessMemory_1458 {
  strings:
    $key_1458 = { 43 2a [2] 71 08 [2] 77 3d [2] 59 3d [2] 66 21 }

  condition:
    any of them
}