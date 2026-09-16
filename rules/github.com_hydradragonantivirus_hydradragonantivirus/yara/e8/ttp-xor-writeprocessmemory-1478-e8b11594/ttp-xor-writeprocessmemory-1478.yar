rule TTP_XOR_WriteProcessMemory_1478 {
  strings:
    $key_1478 = { 43 0a [2] 71 28 [2] 77 1d [2] 59 1d [2] 66 01 }

  condition:
    any of them
}