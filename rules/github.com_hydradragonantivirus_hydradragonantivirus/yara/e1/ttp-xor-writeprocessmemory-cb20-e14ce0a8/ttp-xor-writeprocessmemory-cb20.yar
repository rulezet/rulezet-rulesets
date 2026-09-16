rule TTP_XOR_WriteProcessMemory_cb20 {
  strings:
    $key_cb20 = { 9c 52 [2] ae 70 [2] a8 45 [2] 86 45 [2] b9 59 }

  condition:
    any of them
}