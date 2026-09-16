rule TTP_XOR_WriteProcessMemory_cb2b {
  strings:
    $key_cb2b = { 9c 59 [2] ae 7b [2] a8 4e [2] 86 4e [2] b9 52 }

  condition:
    any of them
}