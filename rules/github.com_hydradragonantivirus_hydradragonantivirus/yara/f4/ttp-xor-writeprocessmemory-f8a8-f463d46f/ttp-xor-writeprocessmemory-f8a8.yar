rule TTP_XOR_WriteProcessMemory_f8a8 {
  strings:
    $key_f8a8 = { af da [2] 9d f8 [2] 9b cd [2] b5 cd [2] 8a d1 }

  condition:
    any of them
}