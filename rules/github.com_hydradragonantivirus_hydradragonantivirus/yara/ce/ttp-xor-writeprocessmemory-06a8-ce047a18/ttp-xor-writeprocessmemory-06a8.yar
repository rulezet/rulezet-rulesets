rule TTP_XOR_WriteProcessMemory_06a8 {
  strings:
    $key_06a8 = { 51 da [2] 63 f8 [2] 65 cd [2] 4b cd [2] 74 d1 }

  condition:
    any of them
}