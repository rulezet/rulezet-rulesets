rule TTP_XOR_WriteProcessMemory_0ba8 {
  strings:
    $key_0ba8 = { 5c da [2] 6e f8 [2] 68 cd [2] 46 cd [2] 79 d1 }

  condition:
    any of them
}