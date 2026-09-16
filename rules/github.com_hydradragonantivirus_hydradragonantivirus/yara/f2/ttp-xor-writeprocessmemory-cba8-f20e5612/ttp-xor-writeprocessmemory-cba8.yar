rule TTP_XOR_WriteProcessMemory_cba8 {
  strings:
    $key_cba8 = { 9c da [2] ae f8 [2] a8 cd [2] 86 cd [2] b9 d1 }

  condition:
    any of them
}