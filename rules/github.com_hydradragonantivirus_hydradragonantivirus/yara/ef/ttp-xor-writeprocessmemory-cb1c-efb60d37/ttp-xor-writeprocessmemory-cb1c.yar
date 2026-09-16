rule TTP_XOR_WriteProcessMemory_cb1c {
  strings:
    $key_cb1c = { 9c 6e [2] ae 4c [2] a8 79 [2] 86 79 [2] b9 65 }

  condition:
    any of them
}