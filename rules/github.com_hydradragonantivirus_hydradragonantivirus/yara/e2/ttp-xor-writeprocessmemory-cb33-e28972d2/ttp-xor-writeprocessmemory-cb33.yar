rule TTP_XOR_WriteProcessMemory_cb33 {
  strings:
    $key_cb33 = { 9c 41 [2] ae 63 [2] a8 56 [2] 86 56 [2] b9 4a }

  condition:
    any of them
}