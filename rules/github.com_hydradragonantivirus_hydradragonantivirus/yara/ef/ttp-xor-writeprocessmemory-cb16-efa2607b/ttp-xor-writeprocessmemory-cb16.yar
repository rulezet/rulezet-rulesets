rule TTP_XOR_WriteProcessMemory_cb16 {
  strings:
    $key_cb16 = { 9c 64 [2] ae 46 [2] a8 73 [2] 86 73 [2] b9 6f }

  condition:
    any of them
}