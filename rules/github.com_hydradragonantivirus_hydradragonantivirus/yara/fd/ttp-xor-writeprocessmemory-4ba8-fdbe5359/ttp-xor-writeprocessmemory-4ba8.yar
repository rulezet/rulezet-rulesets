rule TTP_XOR_WriteProcessMemory_4ba8 {
  strings:
    $key_4ba8 = { 1c da [2] 2e f8 [2] 28 cd [2] 06 cd [2] 39 d1 }

  condition:
    any of them
}