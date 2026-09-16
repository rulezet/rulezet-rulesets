rule TTP_XOR_WriteProcessMemory_cb0b {
  strings:
    $key_cb0b = { 9c 79 [2] ae 5b [2] a8 6e [2] 86 6e [2] b9 72 }

  condition:
    any of them
}