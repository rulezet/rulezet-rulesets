rule TTP_XOR_WriteProcessMemory_00a8 {
  strings:
    $key_00a8 = { 57 da [2] 65 f8 [2] 63 cd [2] 4d cd [2] 72 d1 }

  condition:
    any of them
}