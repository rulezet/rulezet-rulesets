rule TTP_XOR_WriteProcessMemory_198b {
  strings:
    $key_198b = { 4e f9 [2] 7c db [2] 7a ee [2] 54 ee [2] 6b f2 }

  condition:
    any of them
}