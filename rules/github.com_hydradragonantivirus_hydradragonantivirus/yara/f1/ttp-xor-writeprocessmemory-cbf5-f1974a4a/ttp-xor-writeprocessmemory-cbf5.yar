rule TTP_XOR_WriteProcessMemory_cbf5 {
  strings:
    $key_cbf5 = { 9c 87 [2] ae a5 [2] a8 90 [2] 86 90 [2] b9 8c }

  condition:
    any of them
}