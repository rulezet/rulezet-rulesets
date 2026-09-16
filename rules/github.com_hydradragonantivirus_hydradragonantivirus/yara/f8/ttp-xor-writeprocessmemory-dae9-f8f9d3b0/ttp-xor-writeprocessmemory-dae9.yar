rule TTP_XOR_WriteProcessMemory_dae9 {
  strings:
    $key_dae9 = { 8d 9b [2] bf b9 [2] b9 8c [2] 97 8c [2] a8 90 }

  condition:
    any of them
}