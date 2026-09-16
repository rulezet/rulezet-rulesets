rule TTP_XOR_WriteProcessMemory_cbf8 {
  strings:
    $key_cbf8 = { 9c 8a [2] ae a8 [2] a8 9d [2] 86 9d [2] b9 81 }

  condition:
    any of them
}