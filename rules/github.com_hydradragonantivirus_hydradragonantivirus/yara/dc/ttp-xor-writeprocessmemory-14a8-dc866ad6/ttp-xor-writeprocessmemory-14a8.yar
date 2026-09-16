rule TTP_XOR_WriteProcessMemory_14a8 {
  strings:
    $key_14a8 = { 43 da [2] 71 f8 [2] 77 cd [2] 59 cd [2] 66 d1 }

  condition:
    any of them
}