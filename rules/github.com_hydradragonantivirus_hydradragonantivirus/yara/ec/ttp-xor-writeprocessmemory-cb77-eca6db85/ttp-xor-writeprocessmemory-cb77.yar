rule TTP_XOR_WriteProcessMemory_cb77 {
  strings:
    $key_cb77 = { 9c 05 [2] ae 27 [2] a8 12 [2] 86 12 [2] b9 0e }

  condition:
    any of them
}