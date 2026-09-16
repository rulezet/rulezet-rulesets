rule TTP_XOR_WriteProcessMemory_cb06 {
  strings:
    $key_cb06 = { 9c 74 [2] ae 56 [2] a8 63 [2] 86 63 [2] b9 7f }

  condition:
    any of them
}