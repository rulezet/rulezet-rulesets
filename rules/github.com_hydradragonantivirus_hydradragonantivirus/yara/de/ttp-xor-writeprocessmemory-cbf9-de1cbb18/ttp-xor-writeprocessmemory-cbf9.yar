rule TTP_XOR_WriteProcessMemory_cbf9 {
  strings:
    $key_cbf9 = { 9c 8b [2] ae a9 [2] a8 9c [2] 86 9c [2] b9 80 }

  condition:
    any of them
}