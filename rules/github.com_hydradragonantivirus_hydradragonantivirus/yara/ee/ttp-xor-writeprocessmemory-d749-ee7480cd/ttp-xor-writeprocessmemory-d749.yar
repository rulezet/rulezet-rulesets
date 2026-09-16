rule TTP_XOR_WriteProcessMemory_d749 {
  strings:
    $key_d749 = { 80 3b [2] b2 19 [2] b4 2c [2] 9a 2c [2] a5 30 }

  condition:
    any of them
}