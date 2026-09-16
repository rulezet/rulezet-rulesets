rule TTP_XOR_WriteProcessMemory_e5a8 {
  strings:
    $key_e5a8 = { b2 da [2] 80 f8 [2] 86 cd [2] a8 cd [2] 97 d1 }

  condition:
    any of them
}