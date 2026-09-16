rule TTP_XOR_WriteProcessMemory_17a8 {
  strings:
    $key_17a8 = { 40 da [2] 72 f8 [2] 74 cd [2] 5a cd [2] 65 d1 }

  condition:
    any of them
}