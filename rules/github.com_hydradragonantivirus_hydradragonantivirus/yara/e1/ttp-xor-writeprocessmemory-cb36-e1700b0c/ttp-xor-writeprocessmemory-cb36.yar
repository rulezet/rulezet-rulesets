rule TTP_XOR_WriteProcessMemory_cb36 {
  strings:
    $key_cb36 = { 9c 44 [2] ae 66 [2] a8 53 [2] 86 53 [2] b9 4f }

  condition:
    any of them
}