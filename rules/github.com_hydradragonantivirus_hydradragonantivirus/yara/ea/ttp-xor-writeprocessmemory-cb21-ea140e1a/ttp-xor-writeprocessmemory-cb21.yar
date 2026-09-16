rule TTP_XOR_WriteProcessMemory_cb21 {
  strings:
    $key_cb21 = { 9c 53 [2] ae 71 [2] a8 44 [2] 86 44 [2] b9 58 }

  condition:
    any of them
}