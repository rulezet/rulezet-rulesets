rule TTP_XOR_WriteProcessMemory_cb46 {
  strings:
    $key_cb46 = { 9c 34 [2] ae 16 [2] a8 23 [2] 86 23 [2] b9 3f }

  condition:
    any of them
}