rule TTP_XOR_WriteProcessMemory_cbf2 {
  strings:
    $key_cbf2 = { 9c 80 [2] ae a2 [2] a8 97 [2] 86 97 [2] b9 8b }

  condition:
    any of them
}