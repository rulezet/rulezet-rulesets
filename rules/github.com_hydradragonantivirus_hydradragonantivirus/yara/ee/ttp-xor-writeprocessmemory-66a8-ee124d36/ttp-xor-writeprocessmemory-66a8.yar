rule TTP_XOR_WriteProcessMemory_66a8 {
  strings:
    $key_66a8 = { 31 da [2] 03 f8 [2] 05 cd [2] 2b cd [2] 14 d1 }

  condition:
    any of them
}