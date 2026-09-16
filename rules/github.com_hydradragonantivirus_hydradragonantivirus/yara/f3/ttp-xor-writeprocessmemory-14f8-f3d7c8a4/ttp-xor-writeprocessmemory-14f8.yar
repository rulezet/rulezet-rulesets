rule TTP_XOR_WriteProcessMemory_14f8 {
  strings:
    $key_14f8 = { 43 8a [2] 71 a8 [2] 77 9d [2] 59 9d [2] 66 81 }

  condition:
    any of them
}