rule TTP_XOR_WriteProcessMemory_cb40 {
  strings:
    $key_cb40 = { 9c 32 [2] ae 10 [2] a8 25 [2] 86 25 [2] b9 39 }

  condition:
    any of them
}