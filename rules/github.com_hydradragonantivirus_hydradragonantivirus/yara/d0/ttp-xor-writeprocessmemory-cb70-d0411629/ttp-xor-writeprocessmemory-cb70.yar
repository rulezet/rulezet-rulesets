rule TTP_XOR_WriteProcessMemory_cb70 {
  strings:
    $key_cb70 = { 9c 02 [2] ae 20 [2] a8 15 [2] 86 15 [2] b9 09 }

  condition:
    any of them
}