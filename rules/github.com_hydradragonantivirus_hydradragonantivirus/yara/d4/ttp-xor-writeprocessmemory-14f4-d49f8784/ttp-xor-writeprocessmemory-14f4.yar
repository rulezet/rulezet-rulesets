rule TTP_XOR_WriteProcessMemory_14f4 {
  strings:
    $key_14f4 = { 43 86 [2] 71 a4 [2] 77 91 [2] 59 91 [2] 66 8d }

  condition:
    any of them
}